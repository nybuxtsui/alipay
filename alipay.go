package alipay

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const HTTPS_VERIFY_URL = "https://mapi.alipay.com/gateway.do?service=notify_verify&"

var ALI_PUBLIC_KEY *rsa.PublicKey

func init() {
	k := `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCnxj/9qwVfgoUh/y2W89L6BkRA
FljhNhgPdyPuBV64bfQNN1PjbCzkIM6qRdKBoLPXmKKMiFYnkd6rAoprih3/PrQE
B/VsW8OoM8fxn67UDYuyBTqA23MML9q1+ilIZwBC2AQ2UBVOrFXfFl75p6/B5Ksi
NG9zpgmLCUYuLkxpLQIDAQAB
-----END PUBLIC KEY-----`
	p, _ := pem.Decode([]byte(k))
	if key, err := x509.ParsePKIXPublicKey(p.Bytes); err != nil {
		log.Fatalln("load ali public key failed:", err)
	} else {
		ALI_PUBLIC_KEY = key.(*rsa.PublicKey)
	}
}

type AliPay struct {
	Partner     string
	Seller      string
	CallbackURL string

	OnTrade func(map[string][]string)

	privateKey *rsa.PrivateKey
	seedId     int64
}

func (ali *AliPay) LoadPem(filename string) error {
	pemBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Println("load pem failed:", err)
		return err
	}
	p, _ := pem.Decode([]byte(pemBytes))
	return ali.loadPem(p.Bytes)
}

func (ali *AliPay) LoadPrivateKey(pk string) error {
	p, _ := pem.Decode([]byte(pk))
	return ali.loadPem(p.Bytes)
}

func (ali *AliPay) loadPem(pemBytes []byte) error {
	if key, err := x509.ParsePKCS1PrivateKey(pemBytes); err != nil {
		log.Println("load private key failed:", err)
		return err
	} else {
		ali.privateKey = key
		return nil
	}
}

func (ali *AliPay) verify(params map[string]string) bool {
	notifyId := params["notify_id"]
	valid := true
	if notifyId != "" {
		valid = ali.verifyNotifyId(notifyId)
	}
	return ali.checkSign(params) && valid
}

func (ali *AliPay) verifyNotifyId(notify_id string) bool {
	verify_url := HTTPS_VERIFY_URL + "partner=" + ali.Partner + "&notify_id=" + notify_id
	resp, err := http.Get(verify_url)
	if err != nil {
		log.Println("http get failed:", err)
		return false
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("http get failed:", err)
		return false
	}
	return strings.Contains(string(body), "true")
}

func (ali *AliPay) buildURL(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for key, value := range params {
		lowKey := strings.ToLower(key)
		if value == "" || lowKey == "sign" || lowKey == "sign_type" {
			continue
		}
		keys = append(keys, key+"="+value)
	}
	sort.Sort(sort.StringSlice(keys))
	return strings.Join(keys, "&")
}

func (ali *AliPay) checkSign(params map[string]string) bool {
	url := ali.buildURL(params)
	h := sha1.New()
	h.Write([]byte(url))
	sum := h.Sum(nil)
	sign, _ := base64.StdEncoding.DecodeString(params["sign"])
	err := rsa.VerifyPKCS1v15(ALI_PUBLIC_KEY, crypto.SHA1, sum, sign)
	if err != nil {
		log.Println("rsa verify failed:", err)
		return false
	}
	return true
}

func (ali *AliPay) Callback(w http.ResponseWriter, r *http.Request) {
	params := make(map[string]string)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ParseForm()
	for key, values := range r.Form {
		params[key] = strings.Join(values, ",")
	}

	out_trade_no := r.Form.Get("out_trade_no")
	trade_status := r.Form.Get("trade_status")

	if ali.verify(params) {
		ok := false
		if trade_status == "TRADE_FINISHED" {
			ok = true
		} else if trade_status == "TRADE_SUCCESS" {
			ok = true
		}
		if ok {
			//ok
			ali.OnTrade(r.Form)
			log.Println("success:", out_trade_no)
		}
		w.Write([]byte("success"))
	} else { //验证失败
		w.Write([]byte("fail"))
	}
}

func (ali *AliPay) sign(content string) string {
	h := sha1.New()
	h.Write([]byte(content))
	sum := h.Sum(nil)

	b, _ := rsa.SignPKCS1v15(rand.Reader, ali.privateKey, crypto.SHA1, sum)
	return base64.StdEncoding.EncodeToString(b)
}

func (ali *AliPay) GenTradeNo() string {
	id := atomic.AddInt64(&ali.seedId, 1)
	id = id % 10000

	return time.Now().Format("20060102150405") + "_" + strconv.Itoa(int(id))
}

func (ali *AliPay) genOrder(tradeno, subject, body, price string) string {
	temp := `partner="%s"&seller_id="%s"&out_trade_no="%s"&subject="%s"&body="%s"&total_fee="%s"&notify_url="%s"&service="mobile.securitypay.pay"&payment_type="1"&_input_charset="utf-8"&it_b_pay="30m"&return_url="http://m.alipay.com"`
	return fmt.Sprintf(temp, ali.Partner, ali.Seller, tradeno, subject, body, price, ali.CallbackURL)
}

func (pay *AliPay) Buy(tradeno, subject, body, price string) string {
	orderInfo := pay.genOrder(tradeno, subject, body, price)
	sign := pay.sign(orderInfo)
	sign = url.QueryEscape(sign)
	return orderInfo + fmt.Sprintf(`&sign="%s"&sign_type="RSA"`, sign)
}
