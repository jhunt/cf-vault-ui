package vault

import (
	"fmt"
)

func (v *Vault) RenewLease() error {
	res, err := v.Curl("POST", "auth/token/renew-self", nil)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return fmt.Errorf("received HTTP %d response", res.StatusCode)
	}

	return nil
}
