package recaptcha

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
)

type Verifier struct {
	secret string
}

func NewVerifier(secret string) *Verifier {
	return &Verifier{secret: secret}
}

// Verify проверяет токен reCAPTCHA
func (v *Verifier) Verify(token string) (bool, error) {
	form := url.Values{}
	form.Add("secret", v.secret)
	form.Add("response", token)

	resp, err := http.PostForm(
		"https://www.google.com/recaptcha/api/siteverify",
		form,
	)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	var result ReCaptchaResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return false, err
	}

	return result.Success && result.Score >= 0.5, nil
}
