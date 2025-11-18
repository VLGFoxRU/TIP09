package config

import (
	"log"
	"os"
	"strconv"
)

type Config struct {
	DB_DSN     string
	BcryptCost int // Например, 12
	Addr       string
}

func Load() Config {
	cost := 12
	if v := os.Getenv("BCRYPT_COST"); v != "" {
		// необязательно: распарсить int, при ошибке оставить 12
		parseInt, err := strconv.ParseInt(v, 10, 64)
		if err == nil {
			cost = int(parseInt)
		}
	}
	addr := os.Getenv("APP_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	dsn := os.Getenv("DB_DSNU")
	if dsn == "" {
		dsn = "postgres://postgres:1234@localhost:5433/pz9?sslmode=disable"
	}
	log.Printf("Database DSN: %s \nBcrypt cost: %s \n App port: %s", dsn, cost, addr)
	return Config{
		DB_DSN:     dsn,
		BcryptCost: cost,
		Addr:       addr,
	}
}