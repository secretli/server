package main

import (
	"context"
	"database/sql"
	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/secretli/server/ent"
	"github.com/secretli/server/internal/config"
	"github.com/secretli/server/internal/secrets"
	"github.com/secretli/server/internal/server"
	"log"
)

func main() {
	conf, err1 := config.GatherConfig()
	client, err2 := runMigrationAndProvideEntClient()

	if err := errors.Join(err1, err2); err != nil {
		log.Fatalln(err)
	}
	defer client.Close()

	repo := secrets.NewRepository(client)
	service := secrets.NewService(repo)

	svr := server.NewServer(conf, service)
	svr.Use(gin.Logger(), gin.Recovery(), server.ErrorHandler())
	svr.InitRoutes()

	go repo.StartCleanupJob(conf.CleanupInterval)

	if err := svr.Run(); err != nil {
		log.Fatalf("error starting server: %v", err)
	}
}

func runMigrationAndProvideEntClient() (*ent.Client, error) {
	connectionConfig, err := pgx.ParseConfig("")
	if err != nil {
		return nil, err
	}

	connectionString := stdlib.RegisterConnConfig(connectionConfig)
	db, err := sql.Open("pgx", connectionString)
	if err != nil {
		return nil, err
	}

	drv := entsql.OpenDB(dialect.Postgres, db)
	client := ent.NewClient(ent.Driver(drv))

	ctx := context.Background()
	if err = client.Schema.Create(ctx); err != nil {
		return nil, fmt.Errorf("failed migrationg schema: %w", err)
	}

	return client, nil
}
