\name{Rwhois}
\alias{Rwhois}
\alias{Rwhois::whois_query}
\alias{Rwhois::whois_keyextract}
\alias{whois_query}
\alias{whois_keyextract}
\title{WHOIS server querying}
\description{Queries WHOIS servers}
\usage{
whois_query(hostname, server="whois.iana.org",
  follow.refer=TRUE, raw.data=FALSE, debug=FALSE
)
whois_keyextract(query_ret, keys, blacklist_values=NULL, unlist.recursive=TRUE)
}
\arguments{
\item{hostname}{Server hostname (or hostnames as vector) to return results for.}
\item{server}{WHOIS server to query (default: whois.iana.org)}
\item{follow.refer}{Whether to follow referral information from a WHOIS result to query a different WHOIS server.  Default TRUE.}
\item{raw.data}{Whether to dump raw output as a character string without parsing.  Default FALSE.  If TRUE, this option supercedes follow.refer and forces it FALSE.}
\item{query_ret}{data.frame that was returned from whois_query()}
\item{keys}{Single string or vector of strings, case-insensitive, of what keys to look for in-order to return back values of from the whois return}
\item{debug}{Boolean if you want debug prints (good for large quantities of manual data)}
\item{blacklist_values}{Character or vector of values (or starting values) to skip when searching}
\item{unlist.recursive}{Boolean if you want the unlist at the end to pass recursively}
}
\value{
whois_query() returns a data.frame
whois_keyextract() returns a vector
}
\author{Brad Cable}
\examples{
# Grab WHOIS data for an IP
whois_query("1.1.1.1")

# Grab WHOIS data for a hostname from a different whois server
whois_query("bcable.net", server="whois.verisign-grs.com")

# Grab multiple vectorized results
domains <- c("bcable.net", "4.2.2.4")
whois_query(domains)

# Extract Country Info About IP Addresses
ip_addresses <- c("1.1.1.1", "8.8.8.8")
query_ret <- whois_query(ip_addresses)
countries <- whois_keyextract(query_ret, "country")

# Extract Organization Info From Same IPs
organization_names <- whois_keyextract(query_ret,
  c("org-name", "orgname", "organisation", "organization")
)
}
\keyword{Rwhois}
\keyword{whois}
\keyword{whois_query}
\keyword{whois_keyextract}
