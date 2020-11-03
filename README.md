### Solution for managing PowerDNS zones via git

## Usage
1. Create the zone you want manage in PowerDNS server. Zone key will be used as $TOKEN later on.
2. Create the respective zone file inside /zones folder (see example-zone.yaml). Zone file name must match zone name in PowerDNS server created in step 1.
3. Update `apiUrlBase` in `pdns-zoner.go` to point to your PowerDNS API and build the golang binary:

```
$ go get ./...
$ go build pdns-zoner.go
$ ./pdns-zoner.go -h

Usage of ./pdns-zoner:
  -a string
    	PowerDNS API URL (default "https://api.dnsaas.domain.cloud/api")
  -c	Don't apply changes, only check & validate zone file(s)
  -t string
    	PowerDNS token (default "token123")
  -z string
    	Zone file to process (default "your.zone.eu")
    
```
  
4. Update your zone file in PowerDNS
```
pdns-zoner -t $TOKEN -z $ZONEFILE
```
  
  
## CI Integration (Gitlab example) 
1. Build Docker Image to be used in your CI Job. 

```
$ docker build -t powerdns-git:latest .
```

2. Create $TOKEN Secret variable in Gitlab project settings

3. Create CI Job in .gitlab-ci.yaml.
```
image: path-to-your-image-registry/powerdns-git:latest

your.domain.eu:
  stage: update-zone
  variables:
    TOKEN: "$TOKEN"
    ZONEFILE: "zones/yourzone.domain.eu.yaml"
  script:
    - pdns-zoner -t $TOKEN -z $ZONEFILE
  only:
    refs:
      - master
    changes:
      - zones/zone.example.eu.yaml
```
