package restgate

/*
|--------------------------------------------------------------------------
| WARNING
|--------------------------------------------------------------------------
| Never Set HTTPSProtectionOff=true In Production.
| The Key and Password will be exposed and highly unsecure otherwise!
| The database server should also use HTTPS Connection and be hidden away
|
*/

/*
Thanks to Ido Ben-Natan ("IdoBn") for postgres fix.
Thanks to Jeremy Saenz & Brendon Murphy for timing-attack protection
*/

import (
	"crypto/subtle"
	e "github.com/pjebs/jsonerror"
	"gopkg.in/unrolled/render.v1"
	"log"
	"net/http"
	"strings"
)

type KeyStore interface {
	AddKey(key string, secret string) error
	MatchKey(key string, secret string) (result bool, err error)
}

type Config struct {
	ErrorMessages      map[int]map[string]string
	Context            func(r *http.Request, authenticatedKey string)
	Debug              bool
	HTTPSProtectionOff bool //Default is HTTPS Protection On
}

type RESTGate struct {
	headerKeyLabel    string
	headerSecretLabel string
	config            Config
	store             KeyStore
}

func New(headerKeyLabel string, headerSecretLabel string, store KeyStore, config Config) *RESTGate {
	t := &RESTGate{headerKeyLabel: headerKeyLabel, headerSecretLabel: headerSecretLabel, config: config, store: store}
	log.Printf("RestGate initializing")

	if headerKeyLabel == "" { //headerKeyLabel must be defined
		if t.config.Debug == true {
			log.Printf("RestGate: headerKeyLabel is not defined.")
		}
		return nil
	}

	//Default Error Messages
	if t.config.ErrorMessages == nil {
		t.config.ErrorMessages = map[int]map[string]string{
			1:  e.New(1, "No Key Or Secret", "", "com.github.pjebs.restgate").Render(),
			2:  e.New(2, "Unauthorized Access", "", "com.github.pjebs.restgate").Render(),
			3:  e.New(3, "Please use HTTPS connection", "", "com.github.pjebs.restgate").Render(),
			99: e.New(99, "Software Developers have not setup authentication correctly", "", "com.github.pjebs.restgate").Render(),
		}
	} else {
		if _, ok := t.config.ErrorMessages[1]; !ok {
			t.config.ErrorMessages[1] = e.New(1, "No Key Or Secret", "", "com.github.pjebs.restgate").Render()
		}

		if _, ok := t.config.ErrorMessages[2]; !ok {
			t.config.ErrorMessages[2] = e.New(2, "Unauthorized Access", "", "com.github.pjebs.restgate").Render()
		}

		if _, ok := t.config.ErrorMessages[3]; !ok {
			t.config.ErrorMessages[3] = e.New(3, "Please use HTTPS connection", "", "com.github.pjebs.restgate").Render()
		}

		if _, ok := t.config.ErrorMessages[99]; !ok {
			t.config.ErrorMessages[99] = e.New(99, "Software Developers have not setup authentication correctly", "", "com.github.pjebs.restgate").Render()
		}
	}

	//Check if HTTPS Protection has been turned off
	if t.config.HTTPSProtectionOff {
		//HTTPS Protection is off
		log.Printf("\x1b[31mWARNING: HTTPS Protection is off. This is potentially insecure!\x1b[39;49m")
	}

	return t
}

func (self *RESTGate) ServeHTTP(w http.ResponseWriter, req *http.Request, next http.HandlerFunc) {

	//Check if HTTPS Protection has been turned off
	if !self.config.HTTPSProtectionOff {
		//HTTPS Protection is on so we must check it
		if !(strings.EqualFold(req.URL.Scheme, "https") || req.TLS != nil) {
			r := render.New(render.Options{})
			r.JSON(w, http.StatusUnauthorized, self.config.ErrorMessages[3]) //"Please use HTTPS connection"
			return
		}
	}

	//Check key in Header
	key := req.Header.Get(self.headerKeyLabel)
	secret := req.Header.Get(self.headerSecretLabel)

	if key == "" {
		//Authentication Information not included in request
		r := render.New(render.Options{})
		r.JSON(w, http.StatusUnauthorized, self.config.ErrorMessages[1]) //"No Key Or Secret"
		return
	}

	authenticationPassed, err := self.store.MatchKey(key, secret)
	if err != nil {
		if self.config.Debug == true {
			log.Printf("RestGate: Run time error: %+v", err)
		}
		r := render.New(render.Options{})
		jerr := e.New(2, err.Error(), "", "com.github.pjebs.restgate").Render()
		r.JSON(w, http.StatusUnauthorized, jerr) //"Unauthorized Access"
	}
	if !authenticationPassed {
		r := render.New(render.Options{})
		r.JSON(w, http.StatusUnauthorized, self.config.ErrorMessages[2]) //"Unauthorized Access"
	} else {
		if self.config.Context != nil {
			self.config.Context(req, key)
		}
		next(w, req)
	}
}

// secureCompare performs a constant time compare of two strings to limit timing attacks.
func secureCompare(given string, actual string) bool {
	if subtle.ConstantTimeEq(int32(len(given)), int32(len(actual))) == 1 {
		return subtle.ConstantTimeCompare([]byte(given), []byte(actual)) == 1
	} else {
		/* Securely compare actual to itself to keep constant time, but always return false */
		return subtle.ConstantTimeCompare([]byte(actual), []byte(actual)) == 1 && false
	}
}
