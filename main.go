// m.go
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	RED      = "\033[1;31m"
	GREEN    = "\033[32m"
	YELLOW   = "\033[33m"
	BLUE     = "\033[34m"
	PURPLE   = "\033[35m"
	CYAN     = "\033[36m"
	ORANGE   = "\033[38;5;208m"
	BGRED    = "\033[41m"
	BGGREEN  = "\033[42m"
	BGYELLOW = "\033[43m"
	BGBLUE   = "\033[44m"
	BGPURPLE = "\033[45m"
	BGCYAN   = "\033[46m"
	BGORANGE = "\033[48;5;208m"
	CLEAN    = "\033[0m"
)

var lengthCounter = make(map[string]int)
var seenURLs = make(map[string]bool)

func banner() {
	fmt.Println(CYAN + `
       __     __  ___       __          _
      / /__  / /_/   | ____/ /___ ___  (_)___
 __  / / _ \/ __/ /| |/ __  / __ '__ \/ / __ \
/ /_/ /  __/ /_/ ___ / /_/ / / / / / / / / / /
\____/\___/\__/_/  |_\,_/_/ /_/ /_/_/_/_/ /_/
                                   Trabbit0ne` + CLEAN)
}

func isSkipFile(path string) bool {
	re := regexp.MustCompile(`(?i)\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|pdf|zip|rar|mp4|mp3)$`)
	return re.MatchString(path)
}

func isLoginPage(html string) bool {
	re := regexp.MustCompile(`(?i)<input[^>]*type=['"]?password['"]?`)
	return re.MatchString(html)
}

func detectWAF(target string) (bool, string) {
	resp, err := http.Head(target)
	if err != nil {
		fmt.Println(YELLOW + "[!] Error detecting WAF." + CLEAN)
		return false, ""
	}
	headers := resp.Header
	switch {
	case strings.Contains(strings.ToLower(headers.Get("Server")), "cloudflare"):
		return true, "Cloudflare"
	case strings.Contains(strings.ToLower(headers.Get("Server")), "sucuri"):
		return true, "Sucuri"
	case strings.Contains(strings.ToLower(headers.Get("Server")), "incapsula"):
		return true, "Imperva Incapsula"
	case strings.Contains(strings.ToLower(headers.Get("Server")), "mod_security"):
		return true, "ModSecurity"
	case strings.Contains(strings.ToLower(headers.Get("Server")), "f5"):
		return true, "F5 BigIP"
	default:
		return false, ""
	}
}

func waybackAdminPaths(domain string) []string {
	url := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=%s/*&output=text&fl=original&collapse=urlkey", domain)
	resp, err := http.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	lines := strings.Split(string(data), "\n")
	res := []string{}
	re := regexp.MustCompile(`/(admin|login|dashboard|cpanel|auth|manage|backend)[^./]*$`)
	extSkip := regexp.MustCompile(`(?i)\.(jpg|jpeg|png|gif|js|css|svg|woff|pdf|zip|mp3|mp4)$`)
	for _, line := range lines {
		if re.MatchString(line) && !extSkip.MatchString(line) {
			res = append(res, line)
		}
	}
	return res
}

func scan(paths []string, baseURL string) {
	for _, path := range paths {
		if isSkipFile(path) || path == "" {
			continue
		}

		var fullURL string
		if strings.HasPrefix(path, "http") {
			fullURL = path
		} else {
			fullURL = strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(path, "/")
		}

		// Remove query parameters
		baseOnly := fullURL
		if idx := strings.Index(fullURL, "?"); idx != -1 {
			baseOnly = fullURL[:idx]
		}

		// Skip if base URL already seen
		if seenURLs[baseOnly] {
			continue
		}
		seenURLs[baseOnly] = true

		req, _ := http.NewRequest("GET", fullURL, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("[%sCONNECTION FAIL%s] %s\n", BGRED, CLEAN, baseOnly)
			continue
		}

		buf := new(bytes.Buffer)
		buf.ReadFrom(resp.Body)
		html := buf.String()
		resp.Body.Close()

		cl := resp.Header.Get("Content-Length")
		if cl == "" {
			cl = "unknown"
		}
		lengthCounter[cl]++

		code := resp.StatusCode
		switch {
		case code == 200:
			if isSkipFile(baseOnly) || len(html) == 0 {
				fmt.Printf("[%sPOTENTIAL%s] %s - [%s%d%s] (CL: %s)\n", BGORANGE, CLEAN, baseOnly, GREEN, code, CLEAN, cl)
			} else if isLoginPage(html) {
				fmt.Printf("[%sFOUND%s] %s - [%s%d%s] (CL: %s)\n", BGGREEN, CLEAN, baseOnly, GREEN, code, CLEAN, cl)
			} else {
				fmt.Printf("[%sPOTENTIAL%s] %s - [%s%d%s] (CL: %s)\n", BGORANGE, CLEAN, baseOnly, GREEN, code, CLEAN, cl)
			}
		case code == 403:
			fmt.Printf("[%sFORBIDDEN%s] %s - [%s%d%s] (CL: %s)\n", BGYELLOW, CLEAN, baseOnly, RED, code, CLEAN, cl)
		case code == 404:
			fmt.Printf("[%sNOT FOUND%s] %s - [%s%d%s] (CL: %s)\n", RED, CLEAN, baseOnly, RED, code, CLEAN, cl)
		default:
			fmt.Printf("[%sINFO%s] %s - [%d] (CL: %s)\n", CYAN, CLEAN, baseOnly, code, cl)
		}

		time.Sleep(200 * time.Millisecond)
	}
}

func readLines(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		fmt.Println(RED + "[!] Could not open wordlist." + CLEAN)
		os.Exit(1)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf(RED+"[!] Usage: %s <url> [wordlist]\n"+CLEAN, os.Args[0])
		return
	}

	base := os.Args[1]
	if !strings.HasPrefix(base, "http") {
		base = "http://" + base
	}

	wordlist := "admins.txt"
	if len(os.Args) > 2 {
		wordlist = os.Args[2]
	}

	banner()
	paths := readLines(wordlist)
	waf, wafType := detectWAF(base)
	if waf {
		fmt.Println(YELLOW + "[!] WAF detected: " + wafType + CLEAN)
		fmt.Println(BLUE + "[*] WAF detected, scanning Wayback paths first to reduce live requests..." + CLEAN)
		parsed, _ := url.Parse(base)
		scan(waybackAdminPaths(parsed.Host), base)
		fmt.Printf(BLUE+"[*] Scanning with wordlist: %s\n"+CLEAN, wordlist)
		scan(paths, base)
	} else {
		fmt.Println(BLUE + "[*] No WAF detected." + CLEAN)
		fmt.Printf(BLUE+"[*] Scanning with wordlist: %s\n"+CLEAN, wordlist)
		scan(paths, base)
		fmt.Println(BLUE + "[*] Fetching and scanning Wayback admin paths..." + CLEAN)
		parsed, _ := url.Parse(base)
		scan(waybackAdminPaths(parsed.Host), base)
	}

	fmt.Println("\n" + BLUE + "[*] Repeated Content-Lengths:" + CLEAN)
	keys := make([]string, 0, len(lengthCounter))
	for k := range lengthCounter {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if k != "unknown" && lengthCounter[k] >= 3 {
			fmt.Printf("   %s- Pages with Content-Length %s: %d occurrences%s\n", YELLOW, k, lengthCounter[k], CLEAN)
		}
	}
}
