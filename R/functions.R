whois_query_one <- function(hostname, server, debug=FALSE){
	if(debug == TRUE){
		print(paste0("DEBUG: Hostname: ", hostname, collapse=""))
		print(paste0("DEBUG: WHOIS Server: ", server, collapse=""))
	}

	conn <- make.socket(server, 43)
	if(server == "whois.arin.net"){
		# ARIN is unique, "z + " is a special query that just means give me
		# everything you have
		write.socket(conn, paste0(c("z + ", hostname), collapse=""))
	} else {
		# This is the standard WHOIS query protocol
		write.socket(conn, hostname)
	}
	write.socket(conn, "\r\n")

	data <- ""
	cur_read <- "x"
	while(cur_read != ""){
		tryCatch(
			cur_read <- read.socket(conn),
			error=function(e){
				print(paste0("Error (WHOIS Server: ", server, "; Hostname Input: ", hostname))
				print(e)
				cur_read <- ""
			}
		)
		if(cur_read != ""){
			data <- paste0(c(data, cur_read), collapse="")
		}
	}

	close.socket(conn)
	enc2utf8(data)
}

whois_cleanup <- function(data){
	lines <- trimws(strsplit(data, "\n")[[1]])

	# strip commented and blank lines
	lines <- lines[!(substr(lines,1,1) %in% c("%", "#", ""))]

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

whois_query_wrap <- function(hostname, server, raw.data, follow.refer, debug=FALSE){
	raw_data <- whois_query_one(hostname, server, debug=debug)

	if(raw.data){
		strsplit(raw_data, "\n")[[1]]

	} else {
		df <- whois_cleanup(raw_data)
		if(follow.refer && nrow(df)>0 && "refer" %in% df$key){
			refer_key <- row(df)[df$key == "refer"][[1]]
			last_refer <- ""

			while(
				nrow(df) > 0 &&
				df$key[[refer_key]] == "refer" &&
				last_refer != df$key[[refer_key]]
			){
				last_refer <- df$key[[refer_key]]

				raw_data <- whois_query_one(
					hostname, df[1,"val"], debug=debug
				)

				new_df <- whois_cleanup(raw_data)
				if(nrow(new_df) > 0){
					df <- new_df
				}
			}
		}

		if(debug == TRUE){
			print(paste0("DEBUG: Return: ", hostname, collapse=""))
		}
		df
	}
}

whois_query <- function(hostname,
	server="whois.iana.org", follow.refer=TRUE, raw.data=FALSE,
	debug=FALSE
){
	if(length(hostname) > 1){
		lapply(hostname, FUN=function(host){
			whois_query_wrap(host, server, raw.data, follow.refer, debug=debug)
		})
	} else {
		whois_query_wrap(hostname, server, raw.data, follow.refer, debug=debug)
	}
}

whois_keyextract <- function(query_ret, keys){
	whois <- lapply(query_ret, FUN=function(df){
		df$val[tolower(df$key) %in% tolower(keys)]
	})
	whois[sapply(whois, FUN=length) == 0] <- NA

	if(sum(sapply(whois, FUN=length) > 1) != 0){
		whois[sapply(whois, FUN=length) > 1] <-
			sapply(whois[
				sapply(whois, FUN=length) > 1],
				FUN=function(df){ df[[1]] }
			)
	}

	unlist(whois)
}
