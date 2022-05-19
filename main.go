package main

import (
	"context"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v4/pgxpool"
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

	pool, err := openPGConnectionPool()
	if err != nil {
		log.Fatalln(err)
	}
	defer pool.Close()

	repo := repository.NewDBSecretRepository(pool)

	svr := server.NewServer(conf, repo)
	svr.Use(gin.Logger(), gin.Recovery())
	svr.InitRoutes()

	go startHourlyCleanup(repo)

	if err := svr.Run(); err != nil {
		log.Fatalf("error starting server: %v", err)
	}
}

func openPGConnectionPool() (*pgxpool.Pool, error) {
	c, err := pgxpool.ParseConfig("")
	if err != nil {
		return nil, err
	}
	return pgxpool.ConnectConfig(context.Background(), c)
}

func startHourlyCleanup(repo *repository.DBSecretRepository) {
	ticker := time.NewTicker(time.Hour)
	for range ticker.C {
		if err := repo.Cleanup(context.Background(), time.Now()); err != nil {
			log.Printf("error during database cleanup: %s\n", err)
		}
	}
}
