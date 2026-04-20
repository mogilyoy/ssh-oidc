package api

import (
	"crypto/ed25519"
	"os"
)

type User struct {
	Username      string   `json:"Username"`
	Email         string   `json:"Email"`
	UID           int      `json:"UID"`
	GID           int      `json:"GID"`
	FullName      string   `json:"FullName"`
	HomeDirectory string   `json:"HomeDirectory"`
	Shell         string   `json:"Shell"`
	Groups        []string `json:"Groups"`
	SSHKeys       []string `json:"SSHKeys"`
}

type Group struct {
	Name    string   `json:"Name"`
	GID     int      `json:"GID"`
	Members []string `json:"Members"`
	Sudo    bool     `json:"Sudo"`
}

type Server struct {
	issuer  string
	users   map[string]User
	groups  map[string]Group
	privKey ed25519.PrivateKey
	pubKey  ed25519.PublicKey
	jwkID   string
}

var DefaultUsers = []User{
	{
		Username:      "alice",
		Email:         "alice@example.com",
		UID:           1001,
		GID:           1001,
		FullName:      "Alice Example",
		HomeDirectory: "/home/alice",
		Shell:         "/bin/bash",
		Groups:        []string{"cluster-1:admin", "cluster-1:dev"},
		SSHKeys:       []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEzBmFRYe3aWcRKNK1f0Gjv9ug9FiwUbh9M9Ig6G0pcP alice@example.com"},
	},
	{
		Username:      "bob",
		Email:         "bob@example.com",
		UID:           1002,
		GID:           1002,
		FullName:      "Bob Operator",
		HomeDirectory: "/home/bob",
		Shell:         "/bin/bash",
		Groups:        []string{"cluster-1:view"},
		SSHKeys:       []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICM5N6gGZb0EgN9Jdhf7FJp2R2IhQguyyN2XCI+ud1X bob@example.com"},
	},
}

var DefaultGroups = []Group{
	{Name: "cluster-1:admin", GID: 2001, Members: []string{"alice"}, Sudo: true},
	{Name: "cluster-1:dev", GID: 2002, Members: []string{"alice"}, Sudo: false},
	{Name: "cluster-1:view", GID: 2003, Members: []string{"bob"}, Sudo: false},
}

func NewServer() *Server {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	users := make(map[string]User)
	for _, u := range DefaultUsers {
		users[u.Username] = u
	}
	groups := make(map[string]Group)
	for _, g := range DefaultGroups {
		groups[g.Name] = g
	}
	issuer := "http://127.0.0.1:8080"
	if env := os.Getenv("QWE_ISSUER"); env != "" {
		issuer = env
	}
	return &Server{
		issuer:  issuer,
		users:   users,
		groups:  groups,
		privKey: priv,
		pubKey:  pub,
		jwkID:   "local-opkssh-key",
	}
}
