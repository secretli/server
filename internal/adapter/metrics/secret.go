package metrics

import "github.com/prometheus/client_golang/prometheus"

type SecretMetrics struct {
	SecretsCreated prometheus.Counter
	CleanupErrors  prometheus.Counter
}

func NewSecretMetrics(reg *prometheus.Registry) *SecretMetrics {
	m := &SecretMetrics{
		SecretsCreated: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "secrets_created_total",
				Help:      "Total number of secrets created.",
			},
		),
		CleanupErrors: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "cleanup_errors_total",
				Help:      "Total number of errors encountered by the cleanup worker (DB or S3).",
			},
		),
	}
	reg.MustRegister(m.SecretsCreated, m.CleanupErrors)
	return m
}
