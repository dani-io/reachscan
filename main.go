package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Result holds the outcome of testing a single IP
type Result struct {
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	TCPOpen   bool   `json:"tcp_open"`
	TLSOK     bool   `json:"tls_ok"`
	LatencyMs int64  `json:"latency_ms"`
}

// ScanReport is the complete output: metadata + all results
type ScanReport struct {
	ScannerID    string    `json:"scanner_id"`
	StartedAt    time.Time `json:"started_at"`
	FinishedAt   time.Time `json:"finished_at"`
	PublicIP     string    `json:"public_ip"`
	TotalScanned int       `json:"total_scanned"`
	TCPOpen      int       `json:"tcp_open_count"`
	TLSOK        int       `json:"tls_ok_count"`
	Results      []Result  `json:"results"`
}

// Config controls scanner behavior
type Config struct {
	TargetsFile string
	Port        int
	Concurrency int
	Timeout     time.Duration
}

func main() {
	cfg := Config{
		TargetsFile: "targets.txt",
		Port:        443,
		Concurrency: 500,
		Timeout:     3 * time.Second,
	}

	printBanner()

	scannerID := promptScannerID()
	publicIP := detectPublicIP()
	fmt.Printf("[*] Your public IP: %s\n\n", publicIP)

	targets, err := loadTargets(cfg.TargetsFile)
	if err != nil {
		fmt.Printf("\n[ERROR] Cannot read targets.txt: %v\n", err)
		fmt.Println("Make sure targets.txt exists in the same folder as scanner.exe.")
		pause()
		return
	}

	fmt.Printf("[*] Targets loaded:  %d IPs\n", len(targets))
	fmt.Printf("[*] Port:            %d\n", cfg.Port)
	fmt.Printf("[*] Concurrency:     %d\n", cfg.Concurrency)
	fmt.Printf("[*] Timeout:         %s\n\n", cfg.Timeout)

	startedAt := time.Now()
	results := scanAll(targets, cfg)
	finishedAt := time.Now()

	report := buildReport(scannerID, publicIP, startedAt, finishedAt, results)

	// Output filename includes scanner ID to avoid collisions when multiple files arrive
	outFile := fmt.Sprintf("results-%s.json", scannerID)
	if err := saveReport(report, outFile); err != nil {
		fmt.Printf("\n[ERROR] Failed to save results: %v\n", err)
	}

	printSummary(report, outFile)
	pause()
}

func printBanner() {
	fmt.Println("================================================")
	fmt.Println("       IP Whitelist Scanner v1.0")
	fmt.Println("================================================")
}

// promptScannerID asks the user for a name/identifier so results can be tracked.
// Falls back to "anonymous" if nothing entered.
func promptScannerID() string {
	fmt.Println("Please enter a name to identify your scan results.")
	fmt.Println("Example: ali-irancell-tehran")
	fmt.Println("         reza-mci-mashhad")
	fmt.Print("Your name: ")

	reader := bufio.NewReader(os.Stdin)
	id, _ := reader.ReadString('\n')
	id = strings.TrimSpace(id)
	if id == "" {
		id = "anonymous"
	}
	// sanitize: spaces -> dashes, lowercase, strip risky chars
	id = strings.ToLower(strings.ReplaceAll(id, " ", "-"))
	id = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return -1 // drop
	}, id)
	if id == "" {
		id = "anonymous"
	}
	return id
}

// detectPublicIP fetches the user's public IP. Falls back gracefully if there's no internet.
func detectPublicIP() string {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		return "unknown"
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(body))
}

// loadTargets reads IPs from a text file (one per line, blank lines/# comments ignored)
func loadTargets(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var targets []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}
	return targets, scanner.Err()
}

// scanAll runs concurrent scans with a worker pool pattern
func scanAll(targets []string, cfg Config) []Result {
	jobs := make(chan string, cfg.Concurrency)
	resultsChan := make(chan Result, cfg.Concurrency)

	var wg sync.WaitGroup
	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go worker(jobs, resultsChan, cfg, &wg)
	}

	go func() {
		for _, ip := range targets {
			jobs <- ip
		}
		close(jobs)
	}()

	var done int64
	total := int64(len(targets))
	stopProgress := make(chan struct{})
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				d := atomic.LoadInt64(&done)
				pct := float64(d) / float64(total) * 100
				fmt.Printf("\rProgress: %d/%d (%.1f%%)   ", d, total, pct)
			case <-stopProgress:
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var all []Result
	for r := range resultsChan {
		all = append(all, r)
		atomic.AddInt64(&done, 1)
	}
	close(stopProgress)
	fmt.Printf("\rProgress: %d/%d (100.0%%)   \n", total, total)

	return all
}

func worker(jobs <-chan string, results chan<- Result, cfg Config, wg *sync.WaitGroup) {
	defer wg.Done()
	for ip := range jobs {
		results <- testIP(ip, cfg)
	}
}

// testIP performs a TCP connect, then attempts a TLS handshake.
// TLS is the stronger signal — many filters allow TCP but block TLS via SNI inspection.
func testIP(ip string, cfg Config) Result {
	r := Result{IP: ip, Port: cfg.Port}
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", cfg.Port))

	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, cfg.Timeout)
	if err != nil {
		return r
	}
	r.TCPOpen = true
	r.LatencyMs = time.Since(start).Milliseconds()

	// InsecureSkipVerify because we're using IP not hostname; we only care that handshake completes
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         ip,
	})
	tlsConn.SetDeadline(time.Now().Add(cfg.Timeout))
	if err := tlsConn.Handshake(); err == nil {
		r.TLSOK = true
	}
	tlsConn.Close()
	return r
}

// buildReport aggregates results with metadata for upload/comparison
func buildReport(scannerID, publicIP string, startedAt, finishedAt time.Time, results []Result) ScanReport {
	r := ScanReport{
		ScannerID:    scannerID,
		StartedAt:    startedAt,
		FinishedAt:   finishedAt,
		PublicIP:     publicIP,
		TotalScanned: len(results),
		Results:      results,
	}
	for _, res := range results {
		if res.TCPOpen {
			r.TCPOpen++
		}
		if res.TLSOK {
			r.TLSOK++
		}
	}
	return r
}

func saveReport(report ScanReport, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func printSummary(report ScanReport, outputFile string) {
	duration := report.FinishedAt.Sub(report.StartedAt)
	fmt.Println("\n================================================")
	fmt.Println("                  RESULTS")
	fmt.Println("================================================")
	fmt.Printf("Scanner ID:    %s\n", report.ScannerID)
	fmt.Printf("Public IP:     %s\n", report.PublicIP)
	fmt.Printf("Duration:      %s\n", duration.Round(time.Second))
	fmt.Println("------------------------------------------------")
	fmt.Printf("Total scanned: %d\n", report.TotalScanned)
	fmt.Printf("TCP open:      %d\n", report.TCPOpen)
	fmt.Printf("TLS success:   %d   <-- candidates for whitelist\n", report.TLSOK)
	fmt.Println("------------------------------------------------")
	fmt.Printf("Output file:   %s\n", outputFile)
	fmt.Println("================================================")
	fmt.Println()
	fmt.Println(">>> Please send the output file back to the requester. <<<")
}

func pause() {
	fmt.Println("\nPress Enter to exit...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}
