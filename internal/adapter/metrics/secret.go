package metrics

import "github.com/prometheus/client_golang/prometheus"

type SecretMetrics struct {
	SecretsCreated prometheus.Counter
	SecretsCleaned prometheus.Counter
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
		SecretsCleaned: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "secrets_cleaned_total",
				Help:      "Total number of secrets the cleanup removed. Every secret ends there exactly once, whether it expired, was opened once or was deleted.",
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
	reg.MustRegister(m.SecretsCreated, m.SecretsCleaned, m.CleanupErrors)
	return m
}
