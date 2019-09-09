package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/google/go-github/v28/github"
	"golang.org/x/oauth2"
)

var (
	thePath = flag.String("dir", "/tmp", "working directory")
	git     = flag.String("git", "/usr/bin/git", "path to git")
	addr    = flag.String("addr", ":8124", "binding address to listen on")
	secret  = flag.String("secret", "",
		"Optional secret for authenticating hooks")
	ghAPIKey = flag.String("github-api-key", "",
		"Optional key for access GitHub's API")
)

type commandRequest struct {
	w       http.ResponseWriter
	abspath string
	bg      bool
	after   time.Time
	cmds    []*exec.Cmd
	ch      chan bool
}

var reqch = make(chan commandRequest, 100)
var updates = map[string]time.Time{}

func exists(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}
	return true
}

func maybePanic(err error) {
	if err != nil {
		panic(err)
	}
}

func runCommands(w http.ResponseWriter, bg bool,
	abspath string, cmds []*exec.Cmd) {

	stderr := ioutil.Discard
	stdout := ioutil.Discard

	if !bg {
		stderr = &bytes.Buffer{}
		stdout = &bytes.Buffer{}
	}

	for _, cmd := range cmds {
		if exists(cmd.Path) {
			log.Printf("Running %v in %v", cmd.Args, abspath)
			fmt.Fprintf(stdout, "# Running %v\n", cmd.Args)
			fmt.Fprintf(stderr, "# Running %v\n", cmd.Args)

			cmd.Stdout = stdout
			cmd.Stderr = stderr
			cmd.Dir = abspath
			err := cmd.Run()

			if err != nil {
				log.Printf("Error running %v in %v:  %v",
					cmd.Args, abspath, err)
				if !bg {
					fmt.Fprintf(stderr,
						"\n[gitmirror internal error:  %v]\n", err)
				}
			}

		}
	}

	if !bg {
		fmt.Fprintf(w, "---- stdout ----\n")
		_, err := stdout.(*bytes.Buffer).WriteTo(w)
		maybePanic(err)
		fmt.Fprintf(w, "\n----\n\n\n---- stderr ----\n")
		_, err = stderr.(*bytes.Buffer).WriteTo(w)
		maybePanic(err)
		fmt.Fprintf(w, "\n----\n")
	}
}

func shouldRun(path string, after time.Time) bool {
	if path == "/tmp" {
		return true
	}
	lastRun := updates[path]
	return lastRun.Before(after)
}

func didRun(path string, t time.Time) {
	updates[path] = t
}

func pathRunner(ch chan commandRequest) {
	for r := range ch {
		if shouldRun(r.abspath, r.after) {
			t := time.Now()
			runCommands(r.w, r.bg, r.abspath, r.cmds)
			didRun(r.abspath, t)
		} else {
			log.Printf("Skipping redundant update: %v", r.abspath)
			if !r.bg {
				fmt.Fprintf(r.w, "Redundant request.")
			}
		}
		select {
		case r.ch <- true:
		default:
		}
	}
}

func commandRunner() {
	m := map[string]chan commandRequest{}

	for r := range reqch {
		ch, running := m[r.abspath]
		if !running {
			ch = make(chan commandRequest, 10)
			m[r.abspath] = ch
			go pathRunner(ch)
		}
		ch <- r
	}
}

var gitHubAPIMeta *github.APIMeta
var allowedNetworks []*net.IPNet

func hookACLRunner() {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: *ghAPIKey},
	)
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	update := func() {
		meta, _, err := client.APIMeta(ctx)
		if err != nil {
			log.Print(err)
			return
		}

		_, localNet, _ := net.ParseCIDR("127.0.0.1/32")
		nets := []*net.IPNet{localNet}
		for _, cidr := range meta.Hooks {
			_, ipv4Net, err := net.ParseCIDR(cidr)
			if err != nil {
				log.Fatal(err)
			}
			nets = append(nets, ipv4Net)
		}
		allowedNetworks = nets
		gitHubAPIMeta = meta
		//log.Print(meta.Hooks)

		//limits, _, err := client.RateLimits(ctx)
		//log.Print(limits)
	}

	if gitHubAPIMeta == nil {
		update()
	}

	ticker := time.NewTicker(time.Second * 30)
	defer ticker.Stop()

	done := make(chan bool)
	log.Print("Starting GitHub meta polling!")

	for {
		select {
		case <-done:
			log.Print("Done GitHub meta polling!")
		case t := <-ticker.C:
			log.Print(t)
			update()
		}
	}
}

func queueCommand(w http.ResponseWriter, bg bool,
	abspath string, cmds []*exec.Cmd) chan bool {
	req := commandRequest{w, abspath, bg, time.Now(),
		cmds, make(chan bool)}
	reqch <- req
	return req.ch
}

func updateGit(ctx context.Context, w http.ResponseWriter, section string, bg bool, payload []byte) bool {

	abspath := filepath.Join(*thePath, section)

	if !exists(abspath) {
		if !bg {
			http.Error(w, "Not found", http.StatusNotFound)
		}
		return false
	}

	cmds := []*exec.Cmd{
		exec.CommandContext(ctx, *git, "remote", "update", "-p"),
		exec.CommandContext(ctx, *git, "gc", "--auto"),
		exec.CommandContext(ctx, filepath.Join(abspath, "hooks/post-fetch")),
		exec.CommandContext(ctx, filepath.Join(*thePath, "bin/post-fetch")),
	}

	cmds[2].Stdin = bytes.NewBuffer(payload)
	cmds[3].Stdin = bytes.NewBuffer(payload)

	return <-queueCommand(w, bg, abspath, cmds)
}

func getPath(req *http.Request) string {
	if qp := req.URL.Query().Get("name"); qp != "" {
		return filepath.Clean(qp)
	}
	return filepath.Clean(filepath.FromSlash(req.URL.Path))[1:]
}

func createRepo(ctx context.Context, w http.ResponseWriter, section string,
	bg bool, payload []byte) {

	p := struct {
		Repository struct {
			Owner   interface{}
			Private bool
			Name    string
		}
	}{}

	err := json.Unmarshal(payload, &p)
	if err != nil {
		log.Printf("Error unmarshalling data: %v", err)
		http.Error(w, "Error parsing JSON", http.StatusInternalServerError)
		return
	}

	var ownerName string
	switch i := p.Repository.Owner.(type) {
	case string:
		ownerName = i
	case map[string]interface{}:
		if x, ok := i["login"]; ok {
			ownerName = fmt.Sprintf("%v", x)
		} else {
			ownerName = fmt.Sprintf("%v", i["name"])
		}
	}

	repo := fmt.Sprintf("git://github.com/%v/%v.git",
		ownerName, p.Repository.Name)
	if p.Repository.Private {
		repo = fmt.Sprintf("git@github.com:%v/%v.git",
			ownerName, p.Repository.Name)
	}

	if bg {
		ctx = context.Background()
		w.WriteHeader(201)
	}
	abspath := filepath.Join(*thePath, section)
	os.Mkdir(abspath, os.ModePerm)
	cmds := []*exec.Cmd{
		exec.CommandContext(ctx, *git, "clone", "--mirror", "--bare", repo, abspath),
		exec.Command(filepath.Join(abspath, "hooks/post-fetch")),
		exec.Command(filepath.Join(*thePath, "bin/post-fetch")),
	}
	queueCommand(w, true, abspath, cmds)
}

func doUpdate(ctx context.Context, w http.ResponseWriter, path string,
	bg bool, payload []byte) {
	if bg {
		go updateGit(context.Background(), w, path, bg, payload)
		w.WriteHeader(201)
	} else {
		updateGit(ctx, w, path, bg, payload)
	}
}

func handleGet(w http.ResponseWriter, req *http.Request, bg bool) {
	doUpdate(req.Context(), w, getPath(req), bg, nil)
}

// parseForm parses an HTTP POST form from an io.Reader.
func parseForm(r io.Reader) (url.Values, error) {
	maxFormSize := int64(1<<63 - 1)
	maxFormSize = int64(10 << 20) // 10 MB is a lot of text.
	b, err := ioutil.ReadAll(io.LimitReader(r, maxFormSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxFormSize {
		err = errors.New("http: POST too large")
		return nil, err
	}
	return url.ParseQuery(string(b))
}

func checkHMAC(h hash.Hash, sig string) bool {
	got := fmt.Sprintf("sha1=%x", h.Sum(nil))
	return len(got) == len(sig) && subtle.ConstantTimeCompare(
		[]byte(got), []byte(sig)) == 1
}

func handlePost(w http.ResponseWriter, req *http.Request, bg bool) {
	// We're teeing the form parsing into a sha1 HMAC so we can
	// authenticate what we actually parsed (if we *secret is set,
	// anyway)
	mac := hmac.New(sha1.New, []byte(*secret))
	r := io.TeeReader(req.Body, mac)
	form, err := parseForm(r)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	b := []byte(form.Get("payload"))

	if !(*secret == "" || checkHMAC(mac, req.Header.Get("X-Hub-Signature"))) {
		http.Error(w, "not authorized", http.StatusUnauthorized)
		return
	}

	path := getPath(req)

	if exists(filepath.Join(*thePath, path)) {
		doUpdate(req.Context(), w, path, bg, b)
	} else {
		createRepo(req.Context(), w, path, bg, b)
	}
}

func authorized(req *http.Request) bool {
	log.Printf("Validating peer %v", req.RemoteAddr)
	if len(allowedNetworks) == 0 {
		log.Printf("allowedNetworks is empty %v", allowedNetworks)
		return true
	}
	log.Printf("Allowed networks %v", allowedNetworks)

	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		log.Print(err)
		return false
	}

	ip := net.ParseIP(host)
	for _, ipv4Net := range allowedNetworks {
		if ipv4Net.Contains(ip) {
			log.Printf("%v is in %v", ip, ipv4Net)
			return true
		}
		log.Printf("%v is not in %v", ip, ipv4Net)
	}
	return false
}

func handleReq(w http.ResponseWriter, req *http.Request) {
	backgrounded := req.URL.Query().Get("bg") != "false"

	log.Printf("Handling %v %v from %v", req.Method, req.URL.Path, req.RemoteAddr)

	if !authorized(req) {
		http.Error(w, "not authorized", http.StatusUnauthorized)
		return
	}

	switch req.Method {
	case "GET":
		handleGet(w, req, backgrounded)
	case "POST":
		handlePost(w, req, backgrounded)
	default:
		http.Error(w, "Method not allowed",
			http.StatusMethodNotAllowed)
	}
}

func main() {
	flag.Parse()

	log.SetFlags(log.Lmicroseconds)

	go commandRunner()
	go hookACLRunner()

	http.HandleFunc("/", handleReq)
	http.HandleFunc("/favicon.ico",
		func(w http.ResponseWriter, req *http.Request) {
			http.Error(w, "No favicon", http.StatusGone)
		})

	log.Fatal(http.ListenAndServe(*addr, nil))
}
