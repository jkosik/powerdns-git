package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const TIMEOUT = time.Duration(10)

var token = flag.String("t", "token123", "PowerDNS token")
var zonePath = flag.String("z", "your.zone.eu", "Zone file to process")
var apiUrlBase = flag.String("a", "https://api.dnsaas.yourdomain.cloud/api", "PowerDNS API URL")
var checkOnly = flag.Bool("c", false, "Don't apply changes, only check & validate zone file(s)")

type RRSet []struct {
	Name       string     `json:"name"`
	Type       string     `json:"type"`
	TTL        int        `json:"ttl"`
	Records    []Records  `json:"records"`
	Comments   []Comments `json:"comments"`
	ChangeType string     `json:"changetype"`
}

type Records struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

type Comments struct {
	Content string `json:"content"`
	Account string `json:"account"`
}

type Actual struct {
	Account        string        `json:"account"`
	APIRectify     bool          `json:"api_rectify"`
	Dnssec         bool          `json:"dnssec"`
	ID             string        `json:"id"`
	Kind           string        `json:"kind"`
	LastCheck      int           `json:"last_check"`
	Masters        []interface{} `json:"masters"`
	Name           string        `json:"name"`
	NotifiedSerial int           `json:"notified_serial"`
	Nsec3Narrow    bool          `json:"nsec3narrow"`
	Nsec3Param     string        `json:"nsec3param"`
	Rrsets         []struct {
		Comments []struct {
			Account    string `json:"account"`
			Content    string `json:"content"`
			ModifiedAt int    `json:"modified_at"`
		} `json:"comments"`
		Name    string `json:"name"`
		Records []struct {
			Content  string `json:"content"`
			Disabled bool   `json:"disabled"`
		} `json:"records"`
		TTL  int    `json:"ttl"`
		Type string `json:"type"`
	} `json:"rrsets"`
	Serial     int    `json:"serial"`
	SoaEdit    string `json:"soa_edit"`
	SoaEditAPI string `json:"soa_edit_api"`
	URL        string `json:"url"`
}

// === Load Zone configuration from YAML file to Struct ===
func (rr *RRSet) getYaml() *RRSet {

	yamlFile, err := ioutil.ReadFile(*zonePath)
	if err != nil {
		log.Printf("yamlFile.Get err   #%v ", err)
	}
	err = yaml.Unmarshal(yamlFile, rr)
	if err != nil {
		log.Fatalf("Cannot unmarshal. Check YAML format: %v", err)
	}

	return rr
}

// === Load Zone data from PowerDNS API to Struct ===

func pdnsDump(url string, target interface{}) error {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	netClient := &http.Client{Timeout: time.Second * TIMEOUT, Transport: tr}

	req, reqErr := http.NewRequest(http.MethodGet, url, nil)
	if reqErr != nil {
		panic(reqErr.Error())
	}

	req.Header.Set("User-Agent", "sec-dns-manager")
	req.Header.Set("X-API-Key", *token)

	res, resErr := netClient.Do(req)
	if resErr != nil {
		panic(resErr.Error())
	}
	if (res.StatusCode == 404) || (res.StatusCode == 422) {
		//fmt.Println(res.StatusCode)
		bodyBytes, _ := ioutil.ReadAll(res.Body)
		bodyString := string(bodyBytes)
		panic(bodyString)
	}
	defer res.Body.Close()
	return json.NewDecoder(res.Body).Decode(target)
}

// === Pass Zone data to PowerDNS API ===
func pdnsPatch(url string, payload string) {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	netClient := &http.Client{Timeout: time.Second * TIMEOUT, Transport: tr}

	var jsonStr = []byte(payload)
	fmt.Println(payload)
	req, reqErr := http.NewRequest(http.MethodPatch, url, bytes.NewBuffer(jsonStr))
	if reqErr != nil {
		panic(reqErr.Error())
	}

	req.Header.Set("User-Agent", "sec-dns-manager")
	req.Header.Set("X-API-Key", *token)
	req.Header.Set("Content-Type", "application/json")

	res, resErr := netClient.Do(req)
	if resErr != nil {
		panic(resErr.Error())
	}
	if (res.StatusCode == 404) || (res.StatusCode == 422) {
		//fmt.Println(res.StatusCode, res)
		bodyBytes, _ := ioutil.ReadAll(res.Body)
		bodyString := string(bodyBytes)
		panic(bodyString)
	}
	defer res.Body.Close()
}

// === Delete Zone records ===
func pdnsDelete(url string, n string, t string) {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	netClient := &http.Client{Timeout: time.Second * TIMEOUT, Transport: tr}
	payload := fmt.Sprintf("{\"rrsets\": [ {\"name\": \"%v\", \"type\": \"%v\", \"changetype\": \"DELETE\" }]}", n, t)
	fmt.Println(payload)
	var jsonStr = []byte(payload)
	req, reqErr := http.NewRequest(http.MethodPatch, url, bytes.NewBuffer(jsonStr))
	if reqErr != nil {
		panic(reqErr.Error())
	}

	req.Header.Set("User-Agent", "sec-dns-manager")
	req.Header.Set("X-API-Key", *token)
	req.Header.Set("Content-Type", "application/json")

	res, resErr := netClient.Do(req)
	if resErr != nil {
		panic(resErr.Error())
	}
	if (res.StatusCode == 404) || (res.StatusCode == 422) {
		//fmt.Println(res.StatusCode, res)
		bodyBytes, _ := ioutil.ReadAll(res.Body)
		bodyString := string(bodyBytes)
		panic(bodyString)
	}
	defer res.Body.Close()
}

// === Validations ===
func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func validName(name string) bool {
	name = strings.Trim(name, " ")
	re, _ := regexp.Compile(`^([a-zA-Z0-9_]+)([a-zA-Z0-9-_\.]+)([a-zA-Z0-9_]+)$`)
	if re.MatchString(name) {
		return true
	}
	return false
}

func validIP4(ipAddress string) bool {
	ipAddress = strings.Trim(ipAddress, " ")
	re, _ := regexp.Compile(`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`)
	if re.MatchString(ipAddress) {
		return true
	}
	return false
}

func validFqdn(host string) bool {
	re, _ := regexp.Compile(`^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`)
	if re.MatchString(host) {
		return true
	}
	return false
}

func validFqndDotted(host string) bool {
	if !strings.HasSuffix(host, ".") {
		return false
	}
	undotted_host := host[:len(host)-1]

	return validFqdn(undotted_host)
}

func validCname(host string) bool {
	return validFqndDotted(host)
}

func validNs(host string) bool {
	return validFqndDotted(host)
}

func validMx(host string) bool {
	// split the data, use whitespace as separator
	mx_data := strings.Fields(host)

	// not sure if this is rfc compliant
	if len(mx_data) != 2 {
		return false
	}

	re_int, _ := regexp.Compile(`^[0-9]+$`)

	if re_int.MatchString(mx_data[0]) && validFqndDotted(mx_data[1]) {
		return true
	}

	return false
}

func findDuplicates(s []string) bool {
	uniques := make(map[string]bool) // keys are the values from the tested slice
	for _, item := range s {
		//fmt.Println("Filling uniques: ", uniques)
		if _, ok := uniques[item]; ok { // if uniques[item] is true it already exists
			uniques[item] = false // flag as duplicate
			fmt.Println("Duplicate found: ", uniques)
			fmt.Println(item, "is a duplicate")
			panic("Duplicate found.")
		} else {
			uniques[item] = true
		}
	}
	return false
}

// === Main ===
func main() {
	flag.Parse()
	//var zonePath = *zoneFile
	var zoneFileName = filepath.Base(*zonePath)
	var extension = filepath.Ext(zoneFileName)
	var zone = zoneFileName[0 : len(zoneFileName)-len(extension)]
	apiUrl := *apiUrlBase + "/v1/servers/localhost/zones/" + zone + "."
	allowedTypes := []string{"A", "TXT", "CNAME", "MX", "NS"}

	// = Load YAML file to Struct =
	var rr RRSet
	rr.getYaml()
	fmt.Println("=== Loaded YAML file ", *zonePath, " ===", rr)

	// = Checking input YAML file =
	fmt.Println("\n=== LINTING YAML ===")

	// Checking for duplicate Name-Type combinations
	var combo []string
	for i := range rr {
		value := strings.Join([]string{rr[i].Name, "-", rr[i].Type}, "") // create Name-Type slice for subsequent duplicate check
		combo = append(combo, value)
	}
	fmt.Println("Combo: ", combo)
	findDuplicates(combo)

	for i := range rr {
		rr[i].Name = strings.ToLower(rr[i].Name)
		rr[i].Type = strings.ToUpper(rr[i].Type)
		// Check if mandatory fields are present
		if rr[i].Name == "" || rr[i].Type == "" || rr[i].Records == nil {
			panic("Check mandatory fields: Name, Type and Records.")
		}
		// TXT records must be wrapped within \"xxx\" to be processed by PowerDNS API properly
		if rr[i].Type == "TXT" {
			for ii := range rr[i].Records {
				rr[i].Records[ii].Content = fmt.Sprintf("\"%v\"", rr[i].Records[ii].Content)
			}
		}
		// Record Name must be alphanumeric and hyphen(neither dots)
		if !validName(rr[i].Name) && !(rr[i].Type == "NS") {
			fmt.Println("Validation failed for: ",rr[i].Name,"-",rr[i].Type)
			panic("Check host Name. Valid characters: alphanumeric, hyphen.")
		}
		if !validFqdn(rr[i].Name) && rr[i].Type == "NS" {
			panic("Check host Name for NS. Valid characters: alphanumeric, hyphen, dot")
		}
		// Record type must be from "allowedTypes"
		if !stringInSlice(rr[i].Type, allowedTypes) {
			panic("Check record Type.")
		}
		// Content of A records must be valid IPv4 format
		if rr[i].Type == "A" {
			for ii := range rr[i].Records {
				if !validIP4(rr[i].Records[ii].Content) {
					panic("IP Address of the A record is not in valid IPv4 format.")
				}
			}
		}
		// CNAME Content records must contain trailing dot and must be a valid FQDN
		if rr[i].Type == "CNAME" {
			for ii := range rr[i].Records {
				if !validCname(rr[i].Records[ii].Content) {
					panic("CNAME record value is missing trailing dot or is malformed.")
				}
			}
		}
		// NS Content records must contain trailing dot and must be be a valid FQDN
		if rr[i].Type == "NS" {
			for ii := range rr[i].Records {
				if !validNs(rr[i].Records[ii].Content) {
					panic("NS record value is missing trailing dot or is malformed.")
				}
			}
		}
		if rr[i].Type == "MX" {
			for ii := range rr[i].Records {
				if !validMx(rr[i].Records[ii].Content) {
					panic("Check MX record format to match proper format e.g. \"10 host.domain.eu.\".")
				}
			}
		}
	}
	fmt.Println("YAML file checks passed.")

	if !*checkOnly {
		fmt.Println("\n=== UPDATING ZONE ", zone, " ===")

		toBe := make(map[string]string)

		for i := range rr {
			rr[i].Name = strings.ToLower(rr[i].Name)
			if stringInSlice(rr[i].Type, allowedTypes) {

				// if a name is equal to the zone name
				// use the zone name
				index_name := rr[i].Name + "." + zone + "."
				if rr[i].Name == zone && rr[i].Type == "NS" {
					index_name = zone + "."
				}
				toBe[index_name] = rr[i].Type
			}
		}
		fmt.Println("--- To be state (only allowedTypes) ---")
		fmt.Println(toBe)

		// = Load PowerDNS response to Struct =
		apidump := new(Actual) // or &Foo{}
		pdnsDump(apiUrl, apidump)
		fmt.Println("--- As is (only allowedTypes) ---")

		asIs := make(map[string]string)

		for i := range apidump.Rrsets {
			if stringInSlice(apidump.Rrsets[i].Type, allowedTypes) {
				asIs[string(apidump.Rrsets[i].Name)] = string(apidump.Rrsets[i].Type)
			}
		}
		fmt.Println(asIs)

		// = Deleting obsolete records =
		fmt.Println("\n=== TO DELETE (deleting only those RR Sets which are not part of \"to be\") ===")
		toDelete := make(map[string]string)
		for keyA, valA := range asIs {
			found := false
			for keyB, valB := range toBe {
				fmt.Println("Checking (as is)", keyA, valA, "against (to be)", keyB, valB)
				if (keyA == keyB) && (valA == valB) {
					fmt.Println("Matched and break - not deleting existing", keyA, valA, "since it matches \"to be\" record.")
					found = true
					break //asIS found within in toBe, and since we Patched toBe rr set already, we keep this rr set
				} else {
					fmt.Println("...asIS not found within toBE - ", keyA, " is a delete candidate")
				}
			}
			fmt.Println()
			if found == false {
				toDelete[keyA] = valA //keys and values are picked up from asIs - lowercased PowerDNS output
			}

		}

		fmt.Println("--- Delete candidates ---")
		fmt.Println(toDelete)

		fmt.Println("--- Executing deletion ---")
		for n, t := range toDelete {
			pdnsDelete(apiUrl, n, t)
		}

		// = Patching new records =
		fmt.Println("\n=== TO PATCH (patch all \"to be\") ===")
		for i := range rr {

			// Extending Name to fqdn
			rr_fqdn := rr[i].Name + "." + zone + "."
			if rr[i].Name == zone && rr[i].Type == "NS" {
				rr_fqdn = zone + "."
			}
			rr[i].Name = rr_fqdn

			// Create JSON payloads from individual rr sets for delivery to PowerDNS API (Marshal Struct to JSON string )
			b, err := json.Marshal(rr[i])
			if err != nil {
				fmt.Printf("Error: %s", err)
				return
			}

			//Unmarshal for modification
			obj := map[string]interface{}{}
			json.Unmarshal([]byte(string(b)), &obj)
			// Modify ChangeType [REPLACE | DELETE] for API call
			obj["changetype"] = "REPLACE"
			//fmt.Print("Unmarshaled and modified changetype: \n", obj)

			// Marshaling for wrapping. rr set must be a wrapped array witin RRSets JSON object to be consumed properly by PowerDNS
			b2, err := json.Marshal(obj)
			if err != nil {
				fmt.Printf("Error: %s", err)
				return
			}

			payload := "{\"rrsets\":[" + string(b2) + "]}"
			//fmt.Println("Marshaled and wrapped Payload: \n", payload)
			pdnsPatch(apiUrl, payload)

		}
	}

}
