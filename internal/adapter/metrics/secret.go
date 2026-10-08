package metrics

import "github.com/prometheus/client_golang/prometheus"

type SecretMetrics struct {
	SecretsCreated prometheus.Counter
	ObjectsDeleted prometheus.Counter
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
		ObjectsDeleted: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "objects_deleted_total",
				Help:      "Total number of objects the cleanup deleted from storage: those of expired, opened one-time and deleted secrets, and of abandoned uploads.",
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
	reg.MustRegister(m.SecretsCreated, m.ObjectsDeleted, m.CleanupErrors)
	return m
}
