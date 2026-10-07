package apitest

import (
	"net/http"
	"testing"
)

type openedTransfer struct {
	Nameplate   int    `json:"nameplate"`
	SenderToken string `json:"sender_token"`
	ExpiresAt   string `json:"expires_at"`
}

type claimedTransfer struct {
	TransferID    string `json:"transfer_id"`
	ReceiverToken string `json:"receiver_token"`
	Offer         string `json:"offer"`
}

// openTransfer opens a transfer with a random id and offer, as a sender
// would after computing its key-exchange share.
func (a api) openTransfer() (id, offer string, opened openedTransfer) {
	a.t.Helper()
	id, offer = b64(randomBytes(a.t, 32)), b64(randomBytes(a.t, 32))
	a.post("/api/v1/transfers", nil, map[string]string{"transfer_id": id, "offer": offer}).
		expect(a.t, "open transfer", http.StatusCreated, &opened)
	if opened.Nameplate < 1 || opened.Nameplate > 999 || opened.SenderToken == "" {
		a.t.Fatalf("opened = %+v", opened)
	}
	return id, offer, opened
}

func (a api) leg(method, id, leg, token string, payload any) reply {
	a.t.Helper()
	if payload != nil {
		return a.post("/api/v1/transfers/"+id+"/"+leg, bearer(token), payload)
	}
	return a.do(method, "/api/v1/transfers/"+id+"/"+leg, bearer(token), nil)
}

func TestATransferRelaysEachLegOnce(t *testing.T) {
	a := server(t)
	id, offer, opened := a.openTransfer()

	// A nameplate is claimed once, and the claim hands over the offer.
	var claimed claimedTransfer
	a.post("/api/v1/transfers/claim", nil, map[string]int{"nameplate": opened.Nameplate}).
		expect(t, "claim", http.StatusOK, &claimed)
	if claimed.TransferID != id || claimed.Offer != offer || claimed.ReceiverToken == "" {
		t.Fatalf("claimed = %+v", claimed)
	}
	a.post("/api/v1/transfers/claim", nil, map[string]int{"nameplate": opened.Nameplate}).
		expect(t, "second claim", http.StatusConflict, nil)

	// The receiver answers once; the same answer again is fine, another is not.
	answer := map[string]string{"share": b64(randomBytes(t, 32)), "confirmation": b64(randomBytes(t, 32))}
	a.leg(http.MethodPost, id, "answer", opened.SenderToken, answer).expect(t, "answer from the sender", http.StatusForbidden, nil)
	a.leg(http.MethodPost, id, "answer", claimed.ReceiverToken, answer).expect(t, "answer", http.StatusNoContent, nil)
	a.leg(http.MethodPost, id, "answer", claimed.ReceiverToken, answer).expect(t, "the same answer again", http.StatusNoContent, nil)
	other := map[string]string{"share": b64(randomBytes(t, 32)), "confirmation": b64(randomBytes(t, 32))}
	a.leg(http.MethodPost, id, "answer", claimed.ReceiverToken, other).expect(t, "another answer", http.StatusConflict, nil)

	var got map[string]string
	a.leg(http.MethodGet, id, "answer", opened.SenderToken, nil).expect(t, "sender reads the answer", http.StatusOK, &got)
	if got["share"] != answer["share"] || got["confirmation"] != answer["confirmation"] {
		t.Errorf("answer = %v, want %v", got, answer)
	}

	// The sealed link is always 552 bytes; delivering it ends the transfer,
	// and the receiver still gets it afterwards.
	a.leg(http.MethodPost, id, "delivery", opened.SenderToken, map[string]string{"sealed": b64(randomBytes(t, 100))}).
		expect(t, "delivery of the wrong size", http.StatusBadRequest, nil)
	sealed := b64(randomBytes(t, 552))
	a.leg(http.MethodPost, id, "delivery", claimed.ReceiverToken, map[string]string{"sealed": sealed}).
		expect(t, "delivery from the receiver", http.StatusForbidden, nil)
	a.leg(http.MethodPost, id, "delivery", opened.SenderToken, map[string]string{"sealed": sealed}).
		expect(t, "delivery", http.StatusNoContent, nil)
	a.leg(http.MethodGet, id, "delivery", claimed.ReceiverToken, nil).expect(t, "receiver reads the delivery", http.StatusOK, &got)
	if got["sealed"] != sealed {
		t.Error("the delivery came back changed")
	}
	a.leg(http.MethodGet, id, "delivery", b64(randomBytes(t, 32)), nil).expect(t, "delivery with a wrong token", http.StatusForbidden, nil)
}

func TestClaimsNeedAValidOpenNameplate(t *testing.T) {
	a := server(t)
	a.post("/api/v1/transfers/claim", nil, map[string]int{"nameplate": 0}).expect(t, "nameplate 0", http.StatusBadRequest, nil)
	a.post("/api/v1/transfers/claim", nil, map[string]int{"nameplate": 1000}).expect(t, "nameplate 1000", http.StatusBadRequest, nil)
	a.post("/api/v1/transfers/claim", nil, map[string]int{"nameplate": 999}).expect(t, "nameplate nobody opened", http.StatusNotFound, nil)

	id, offer := b64(randomBytes(t, 32)), b64(randomBytes(t, 32))
	a.post("/api/v1/transfers", nil, map[string]string{"transfer_id": id, "offer": offer}).expect(t, "open", http.StatusCreated, nil)
	a.post("/api/v1/transfers", nil, map[string]string{"transfer_id": id, "offer": offer}).expect(t, "the same id again", http.StatusConflict, nil)
	a.post("/api/v1/transfers", nil, map[string]string{"transfer_id": "short", "offer": offer}).expect(t, "a malformed id", http.StatusBadRequest, nil)
}

func TestAClosedTransferTellsWhy(t *testing.T) {
	a := server(t)
	id, _, opened := a.openTransfer()
	var claimed claimedTransfer
	a.post("/api/v1/transfers/claim", nil, map[string]int{"nameplate": opened.Nameplate}).
		expect(t, "claim", http.StatusOK, &claimed)

	a.do(http.MethodDelete, "/api/v1/transfers/"+id+"?reason=whatever", bearer(claimed.ReceiverToken), nil).
		expect(t, "close with an unknown reason", http.StatusBadRequest, nil)
	// The receiver found the code did not match.
	a.do(http.MethodDelete, "/api/v1/transfers/"+id+"?reason=mismatch", bearer(claimed.ReceiverToken), nil).
		expect(t, "close", http.StatusNoContent, nil)

	// The sender, waiting for the answer, learns why at once.
	var ended gone
	a.leg(http.MethodGet, id, "answer", opened.SenderToken, nil).expect(t, "sender waits after the close", http.StatusGone, &ended)
	if ended.Details["reason"] != "mismatch" {
		t.Errorf("reason = %v", ended.Details)
	}
	// Nothing can be written any more. (That the nameplate is free again is
	// not checked here: tests run in parallel, and another one may already
	// hold it.)
	a.leg(http.MethodPost, id, "answer", claimed.ReceiverToken, map[string]string{"share": b64(randomBytes(t, 32)), "confirmation": b64(randomBytes(t, 32))}).
		expect(t, "answer after the close", http.StatusGone, nil)
}
