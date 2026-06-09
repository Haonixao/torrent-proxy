package decoy

import (
	"context"
	"log"
	"math/rand"
	"net/http"
	"time"
)

var defaultDecoyHosts = []string{
	"https://www.bing.com",
	"https://www.yahoo.com",
	"https://www.duckduckgo.com",
	"https://www.ebay.com",
	"https://www.booking.com",
	"https://www.tripadvisor.com",
	"https://www.paypal.com",
	"https://www.nvidia.com",
	"https://www.intel.com",
	"https://www.adobe.com",
	"https://www.oracle.com",
	"https://www.ibm.com",
	"https://www.samsung.com",
	"https://www.sony.com",
	"https://www.debian.org",
	"https://www.kernel.org",
	"https://www.docker.com",
	"https://www.python.org",
}

// StartGlobalDecoy запускает фоновые HTTP запросы напрямую (не через туннель)
// для размытия статистики соединений клиента в глазах провайдера.
func StartGlobalDecoy(ctx context.Context) {
	log.Printf("[INFO] Decoy: Starting global background traffic (direct mode)")

	client := &http.Client{
		Timeout: 15 * time.Second,
		// Используем транспорт по умолчанию, чтобы запросы шли напрямую
		Transport: http.DefaultTransport,
	}

	for {
		// Рандомная пауза от 1 до 5 минут
		jitter := time.Duration(rand.Intn(240)+60) * time.Second

		select {
		case <-ctx.Done():
			return
		case <-time.After(jitter):
		}

		// Выполняем 1-3 запроса за раз
		numReqs := rand.Intn(3) + 1
		for i := 0; i < numReqs; i++ {
			host := defaultDecoyHosts[rand.Intn(len(defaultDecoyHosts))]

			go func(url string) {
				req, err := http.NewRequest("HEAD", url, nil)
				if err != nil {
					return
				}
				// Эмулируем браузер
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

				resp, err := client.Do(req)
				if err == nil {
					resp.Body.Close()
					// log.Printf("[DEBUG] Decoy: HEAD %s successful", url)
				}
			}(host)

			// Небольшая пауза между запросами в пачке
			time.Sleep(time.Duration(rand.Intn(500)+100) * time.Millisecond)
		}
	}
}
