package helper

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

func loadConfig() []string {
	apiToken := os.Getenv("PRITOKEN")
	apiSecret := os.Getenv("PRISECRET")
	apiURI := os.Getenv("PRIURI")

	return []string{apiToken, apiSecret, apiURI}
}

func CallAPI(queryData []string) string {
	config := loadConfig()

	authTimestamp := strconv.FormatInt(time.Now().Unix(), 10)
	authNonce := strings.Replace((uuid.New()).String(), "-", "", -1)
	rawAuthString := []string{config[0], authTimestamp, authNonce, queryData[0], queryData[1]}
	authString := strings.Join(rawAuthString, "&")

	hmacv := hmac.New(sha256.New, []byte(config[1]))
	hmacv.Write([]byte(authString))

	signature := base64.StdEncoding.EncodeToString(hmacv.Sum(nil))

	rawQuery := []string{config[2], queryData[1]}
	endpoint := strings.Join(rawQuery, "/")

	client := &http.Client{}
	req, err := http.NewRequest(queryData[0], endpoint, nil)
	if err != nil {
		fmt.Println(err)
	}

	req.Header.Add("Auth-Token", config[0])
	req.Header.Add("Auth-Timestamp", authTimestamp)
	req.Header.Add("Auth-Nonce", authNonce)
	req.Header.Add("Auth-Signature", signature)
	req.Header.Add("Content-Type", "application/json")

	fmt.Println(req)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("TestApiCall: Error on HTTP request: %s", err)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		fmt.Printf("Non-200 response on the tests api call\nbody=%s", body)
	}

	// 401 - invalid credentials
	if resp.StatusCode == 401 {
		fmt.Printf("unauthorized: Invalid token or secret")
	}

	return signature
}
