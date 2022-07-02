Rwhois 1.0.11
=============

R package that queries WHOIS servers.

# Installation #

## Production/CRAN install ##

This package is available in [CRAN](https://bcable.net/x/Rwhois/CRAN).

```
install.packages("Rwhois")
```

## Development/GIT Install ##

To install the development or GIT repository version, this requires the "devtools" package available in [CRAN](https://cran.r-project.org/package=devtools).

### Install devtools ###

Assuming you don't already have devtools installed, run the following:

```
install.packages("devtools")
```

### Install Rwhois ###

With devtools installed, it's fairly simple to install the development branch:

```
library(devtools)
install_git("https://gitlab.com/BCable/Rwhois.git")
```

# Examples #

```r
library(Rwhois)

# Grab WHOIS data for a hostname
whois_query("bcable.net")

# Grab WHOIS data for an IP
whois_query("1.1.1.1")

# Grab WHOIS data for a hostname from a different whois server
whois_query("bcable.net", server="whois.verisign-grs.com")

# Grab multiple vectorized results
domains <- c("bcable.net", "duckduckgo.com")
whois_query(domains)

# Extract Country Info About IP Addresses
ip_addresses <- c("1.1.1.1", "4.2.2.4", "8.8.8.8")
ret <- whois_query(ip_addresses)
countries <- whois_keyextract(ret, "country")

# Extract Organization Info About Hostnames
ret <- whois_query(hostnames)
organization_names <- whois_keyextract(ret,
	c("org-name", "orgname", "organisation", "organization")
)
```
