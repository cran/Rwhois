\name{Rwhois}
\alias{Rwhois}
\alias{Rwhois::whois_query}
\alias{whois_query}
\title{WHOIS server querying}
\description{Queries WHOIS servers}
\usage{
whois_query(hostname, server="whois.iana.org", follow.refer=TRUE, raw.data=FALSE)
}
\arguments{
\item{hostname}{Server hostname (or hostnames as vector) to return results for.}
\item{server}{WHOIS server to query (default: whois.iana.org)}
\item{follow.refer}{Whether to follow referral information from a WHOIS result to query a different WHOIS server.  Default TRUE.}
\item{raw.data}{Whether to dump raw output as a character string without parsing.  Default FALSE.  If TRUE, this option supercedes follow.refer and forces it FALSE.}
}
\value{
whois_query() returns a data.frame
}
\author{Brad Cable}
\examples{
# Grab WHOIS data for a hostname
whois_query("bcable.net")

# Grab WHOIS data for an IP
whois_query("1.1.1.1")

# Grab WHOIS data for a hostname from a different whois server
whois_query("bcable.net", server="whois.verisign-grs.com")

# Grab multiple vectorized results
domains <- c("bcable.net", "google.com")
whois_query(domains)
}
\keyword{Rwhois}
\keyword{whois}
