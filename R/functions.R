whois_query_one <- function(hostname, server){
	conn <- make.socket(server, 43)
	write.socket(conn, hostname)
	write.socket(conn, "\n")

	data <- ""
	cur_read <- "x"
	while(cur_read != ""){
		cur_read <- read.socket(conn)
		data <- paste0(c(data, cur_read), collapse="")
	}

	close.socket(conn)
	data
}

whois_cleanup <- function(data){
	lines <- trimws(strsplit(data, "\n")[[1]])

	# strip commented and blank lines
	lines <- lines[!(substr(lines,1,1) %in% c("%", ""))]

	# strip everything after ">>>" row
	lines <- lines[cumsum(!is.na(str_locate(lines, ">>>")[,"start"])) == 0]

	# split at colon
	colon_loc <- str_locate(lines, ":")[,"start"]
	lines <- lines[!is.na(colon_loc)]
	colon_loc <- colon_loc[!is.na(colon_loc)]

	data.frame(
		key=trimws(substr(lines, 1, colon_loc-1)),
		val=trimws(substr(lines, colon_loc+1, nchar(lines)))
	)
}

whois_query_wrap <- function(hostname, server, raw.data, follow.refer){
	raw_data <- whois_query_one(hostname, server)

	if(raw.data){
		strsplit(raw_data, "\n")[[1]]

	} else {
		df <- whois_cleanup(raw_data)
		if(follow.refer){
			while(df[1,"key"] == "refer"){
				raw_data <- whois_query_one(
					hostname, df[1,"val"]
				)
				df <- whois_cleanup(raw_data)
			}
		}
		df
	}
}

whois_query <- function(hostname,
	server="whois.iana.org", follow.refer=TRUE, raw.data=FALSE
){
	if(length(hostname) > 1){
		lapply(hostname, FUN=function(host){
			whois_query_wrap(host, server, raw.data, follow.refer)
		})
	} else {
		whois_query_wrap(hostname, server, raw.data, follow.refer)
	}
}
