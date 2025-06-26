package plg_authenticate_ldap

import (
	"fmt"
	"github.com/go-ldap/ldap/v3" // Import the go-ldap library
	. "github.com/mickael-kerjean/filestash/server/common"
	"net/http"
	"strconv"
	"strings"
)

func init() {
	Hooks.Register.AuthenticationMiddleware("ldap", Ldap{})
}

type Ldap struct{}

func (this Ldap) Setup() Form {
	return Form{
		Elmnts: []FormElement{
			{
				Name: "banner",
				Type: "hidden",
				Description: `This enterprise SSO plugin delegates authentication to an LDAP server, presenting users with a username and password login page. Their credentials are then verified against your LDAP directory.

The plugin exposes the LDAP attribute of the authenticated users which can be used in the attribute mapping section to create rules tailored to your specific use case, see the documentation [on the website](https://www.filestash.app/setup-ldap.html).
`,
			},
			{
				Name:  "type",
				Type:  "hidden",
				Value: "ldap",
			},
			{
				Name:        "Hostname",
				Type:        "text",
				Value:       "",
				Placeholder: "eg: ldap.example.com",
			},
			{
				Name:        "Port",
				Type:        "text",
				Value:       "",
				Placeholder: "eg: 389",
			},
			{
				Name:        "Bind DN",
				Type:        "text",
				Value:       "",
				Placeholder: "Bind DN",
			},
			{
				Name:        "Bind DN Password",
				Type:        "password",
				Value:       "",
				Placeholder: "Bind CN Password",
			},
			{
				Name:        "Base DN",
				Type:        "text",
				Value:       "",
				Placeholder: "Base DN",
			},
			{
				Name:        "Search Filter",
				Type:        "text",
				Value:       "",
				Placeholder: "default: (&(objectclass=person)(|(uid={{.username}})(mail={{.username}})(sAMAccountName={{.username}})))",
			},
		},
	}
}

func (this Ldap) EntryPoint(idpParams map[string]string, req *http.Request, res http.ResponseWriter) error {
	getFlash := func() string {
		c, err := req.Cookie("flash")
		if err != nil {
			return ""
		}
		http.SetCookie(res, &http.Cookie{
			Name:   "flash",
			MaxAge: -1,
			Path:   "/",
		})
		return fmt.Sprintf(`<p class="flash">%s</p>`, c.Value)
	}
	res.Header().Set("Content-Type", "text/html; charset=utf-8")
	res.WriteHeader(http.StatusOK)
	res.Write([]byte(Page(`
			<form action="` + WithBase("/api/session/auth/") + `" method="post" class="component_middleware">
				<label>
					<input type="text" name="user" value="" placeholder="User" autocorrect="off" autocapitalize="off" />
				</label>
				<label>
					<input type="password" name="password" value="" placeholder="Password" />
				</label>
				<button>CONNECT</button>
				` + getFlash() + `
				<style>
					.flash{ color: #f26d6d; font-weight: bold; }
					form { padding-top: 10vh; }
				</style>
			</form>`)))
	return nil
}

func (this Ldap) Callback(formData map[string]string, idpParams map[string]string, res http.ResponseWriter) (map[string]string, error) {
	username := formData["user"]
	password := formData["password"]

	// Retrieve LDAP configuration from idpParams using the new field names
	ldapHost := idpParams["Hostname"]
	ldapPortStr := idpParams["Port"]
	bindDN := idpParams["Bind DN"]
	bindPassword := idpParams["Bind DN Password"]
	userSearchBase := idpParams["Base DN"]
	userFilter := idpParams["Search Filter"]

	// Validate required parameters
	if ldapHost == "" || ldapPortStr == "" || userSearchBase == "" || userFilter == "" {
		Log.Error("plg_authenticate_ldap::callback missing required LDAP configuration: Hostname, Port, Base DN, or Search Filter")
		http.SetCookie(res, &http.Cookie{
			Name:   "flash",
			Value:  "LDAP configuration error: Missing required fields",
			MaxAge: 1,
			Path:   "/",
		})
		return nil, ErrAuthenticationFailed
	}

	// Parse port
	ldapPort, err := strconv.Atoi(ldapPortStr)
	if err != nil {
		Log.Error("plg_authenticate_ldap::callback invalid LDAP port '%s': %v", ldapPortStr, err)
		http.SetCookie(res, &http.Cookie{
			Name:   "flash",
			Value:  "LDAP configuration error: Invalid port",
			MaxAge: 1,
			Path:   "/",
		})
		return nil, ErrAuthenticationFailed
	}

	// Establish LDAP connection - prioritize non-TLS (plain LDAP)
	var l *ldap.Conn
	address := fmt.Sprintf("%s:%d", ldapHost, ldapPort)

	Log.Debug("Connecting to LDAP server: %s (non-TLS first)", address)
	l, err = ldap.Dial("tcp", address)
	if err != nil {
		Log.Error("plg_authenticate_ldap::callback failed to connect to LDAP server %s: %v", address, err)
		http.SetCookie(res, &http.Cookie{
			Name:   "flash",
			Value:  "Failed to connect to LDAP server",
			MaxAge: 1,
			Path:   "/",
		})
		return nil, ErrAuthenticationFailed
	}

	defer l.Close() // Ensure the connection is closed

	// If not already LDAPS port (636), attempt StartTLS to upgrade the connection
	if ldapPort != 636 {
		Log.Debug("Attempting to start TLS for LDAP connection.")
		err = l.StartTLS(nil) // Use default TLS config (no insecure skip verify)
		if err != nil {
			// Log a warning but continue if StartTLS fails, as per user's request to focus on non-TLS
			Log.Warning("plg_authenticate_ldap::callback failed to start TLS: %v (continuing without TLS)", err)
		}
	}

	// Bind to LDAP (either anonymous or with bind_dn/bind_password)
	if bindDN != "" && bindPassword != "" {
		Log.Debug("Binding to LDAP as: %s", bindDN)
		err = l.Bind(bindDN, bindPassword)
		if err != nil {
			Log.Error("plg_authenticate_ldap::callback initial bind failed for %s: %v", bindDN, err)
			http.SetCookie(res, &http.Cookie{
				Name:   "flash",
				Value:  "LDAP bind failed (check bind DN/password)",
				MaxAge: 1,
				Path:   "/",
			})
			return nil, ErrAuthenticationFailed
		}
	} else {
		Log.Debug("Binding to LDAP anonymously.")
		err = l.Bind("", "") // Anonymous bind
		if err != nil {
			Log.Error("plg_authenticate_ldap::callback anonymous bind failed: %v", err)
			http.SetCookie(res, &http.Cookie{
				Name:   "flash",
				Value:  "LDAP anonymous bind failed",
				MaxAge: 1,
				Path:   "/",
			})
			return nil, ErrAuthenticationFailed
		}
	}

	// Replace the placeholder in the search filter with the escaped username
	searchFilter := strings.ReplaceAll(userFilter, "{{.username}}", ldap.EscapeFilter(username))
	Log.Debug("Searching for user '%s' with filter '%s' in base '%s'", username, searchFilter, userSearchBase)

	// User attribute for search is implicitly "dn" as it's not exposed in the form
	searchRequest := ldap.NewSearchRequest(
		userSearchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		searchFilter,
		[]string{"dn"}, // Always request the DN for the final bind
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		Log.Error("plg_authenticate_ldap::callback LDAP search failed for user '%s': %v", username, err)
		http.SetCookie(res, &http.Cookie{
			Name:   "flash",
			Value:  "Invalid username or password",
			MaxAge: 1,
			Path:   "/",
		})
		return nil, ErrAuthenticationFailed
	}

	if len(sr.Entries) == 0 {
		Log.Warning("plg_authenticate_ldap::callback user '%s' not found in LDAP or filter did not match", username)
		http.SetCookie(res, &http.Cookie{
			Name:   "flash",
			Value:  "Invalid username or password",
			MaxAge: 1,
			Path:   "/",
		})
		return nil, ErrAuthenticationFailed
	}

	if len(sr.Entries) > 1 {
		Log.Warning("plg_authenticate_ldap::callback multiple entries found for user '%s', using the first one.", username)
	}

	// The canonical DN of the found user is used for the authentication bind
	userAuthDN := sr.Entries[0].DN
	Log.Debug("For final bind, using canonical user DN: %s", userAuthDN)

	// Bind as the user with the provided password to authenticate
	Log.Debug("Attempting to bind as user DN: %s", userAuthDN)
	err = l.Bind(userAuthDN, password)
	if err != nil {
		Log.Warning("plg_authenticate_ldap::callback user '%s' authentication failed: %v", username, err)
		http.SetCookie(res, &http.Cookie{
			Name:   "flash",
			Value:  "Invalid username or password",
			MaxAge: 1,
			Path:   "/",
		})
		return nil, ErrAuthenticationFailed
	}

	Log.Info("plg_authenticate_ldap::callback user '%s' authenticated successfully via LDAP", username)

	// Return relevant user information
	return map[string]string{
		"user":     username,
		"password": password,
		"dn":       sr.Entries[0].DN, // Always return the full DN of the authenticated user
	}, nil
}
