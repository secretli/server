package main

import (
	"context"
	"database/sql"
	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/secretli/server/ent"
	"github.com/secretli/server/internal/config"
	"github.com/secretli/server/internal/repository"
	"github.com/secretli/server/internal/server"
	"log"
	"time"
)

func main() {
	conf, err := config.GatherConfig()
	if err != nil {
		log.Fatalln(err)
	}

	client, err := provideEntClient()
	if err != nil {
		log.Fatalln(err)
	}
	defer client.Close()

	ctx := context.Background()
	if err := client.Schema.Create(ctx); err != nil {
		log.Fatalf("failed creating schema resources: %v", err)
	}

	repo := repository.NewDBSecretRepository(client)

	svr := server.NewServer(conf, repo)
	svr.Use(gin.Logger(), gin.Recovery())
	svr.InitRoutes()

	go startHourlyCleanup(repo)

	if err := svr.Run(); err != nil {
		log.Fatalf("error starting server: %v", err)
	}
}

func provideEntClient() (*ent.Client, error) {
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
	return client, nil
}

func startHourlyCleanup(repo *repository.DBSecretRepository) {
	ticker := time.NewTicker(time.Hour)
	for range ticker.C {
		if err := repo.Cleanup(context.Background(), time.Now()); err != nil {
			log.Printf("error during database cleanup: %s\n", err)
		}
	}
}
