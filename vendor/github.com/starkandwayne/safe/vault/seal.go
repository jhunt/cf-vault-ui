package vault

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"regexp"
)

func (v *Vault) SealKeys() (int, error) {
	res, err := v.Curl("GET", "sys/seal-status", nil)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return 0, fmt.Errorf("received HTTP %d response (to /v1/sys/seal-status)", res.StatusCode)
	}

	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return 0, err
	}

	var data = struct {
		Keys int `json:"t"`
	}{}
	err = json.Unmarshal(b, &data)
	if err != nil {
		return 0, err
	}
	return data.Keys, nil
}

func (v *Vault) Seal() (bool, error) {
	res, err := v.Curl("PUT", "sys/seal", nil)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	if res.StatusCode == 500 {
		if b, err := ioutil.ReadAll(res.Body); err == nil {
			if matched, _ := regexp.Match("cannot seal when in standby mode", b); matched {
				return false, nil
			}
		}
	}
	if res.StatusCode != 204 {
		return false, fmt.Errorf("received HTTP %d response", res.StatusCode)
	}
	return true, nil
}

func (v *Vault) Unseal(keys []string) error {
	res, err := v.Curl("PUT", "sys/unseal", []byte(`{"reset":true}`))
	if err != nil {
		return err
	}
	res.Body.Close()

	if res.StatusCode != 200 {
		return fmt.Errorf("received HTTP %d response", res.StatusCode)
	}

	for _, k := range keys {
		res, err := v.Curl("PUT", "sys/unseal", []byte(`{"key":"`+k+`"}`))
		if err != nil {
			return err
		}
		res.Body.Close()

		if res.StatusCode != 200 {
			return fmt.Errorf("received HTTP %d response", res.StatusCode)
		}
	}
	return nil
}
