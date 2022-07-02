whois_query_one <- function(hostname, server, debug=FALSE){
	error_envir <- new.env(parent=baseenv())

	if(debug == TRUE){
		print(paste0("DEBUG: Hostname: ", hostname, collapse=""))
		print(paste0("DEBUG: WHOIS Server: ", server, collapse=""))
	}

	assign("error", FALSE, envir=error_envir)
	for(i in 1:5){
		if(i!=1){
			if(!mget("error", envir=error_envir)[["error"]]){
				break;
			} else {
				Sys.sleep(0.5);
			}
		}

		tryCatch(
			conn <- make.socket(server, 43),
			error=function(e){
				print(paste0(e, " on connection, retrying..."))
				assign("error", TRUE, envir=error_envir)
			}
		)
	}

	assign("error", FALSE, envir=error_envir)
	for(i in 1:5){
		if(i!=1){
			if(!mget("error", envir=error_envir)[["error"]]){
				break;
			} else {
				Sys.sleep(0.5);
			}
		}

		if(server == "whois.arin.net"){
			# ARIN is unique, "z + " is a special query that just means give me
			# everything you have
			tryCatch(
				write.socket(conn, paste0(c("z + ", hostname), collapse="")),
				error=function(e){
					print(paste0(e, " on ARIN header write, retrying..."))
					assign("error", TRUE, envir=error_envir)
				}
			)
		} else {
			# This is the standard WHOIS query protocol
			tryCatch(
				write.socket(conn, hostname),
				error=function(e){
					print(paste0(e, " on header write, retrying..."))
					assign("error", TRUE, envir=error_envir)
				}
			)
		}
	}

	assign("error", FALSE, envir=error_envir)
	for(i in 1:5){
		if(i!=1){
			if(!mget("error", envir=error_envir)[["error"]]){
				break;
			} else {
				Sys.sleep(0.5);
			}
		}

		tryCatch(
			write.socket(conn, "\r\n"),
			error=function(e){
				print(paste0(e, " on header finalize, retrying..."))
				assign("error", TRUE, envir=error_envir)
			}
		)
	}

	if(mget("error", envir=error_envir)[["error"]]){
		NA
	} else {

		data <- ""
		cur_read <- "x"
		while(cur_read != ""){
			tryCatch(
				cur_read <- read.socket(conn),
				error=function(e){
					print(paste0(
						"Error (WHOIS Server: ", server,
						"; Hostname Input: ", hostname, ")"
					))
					print(e)
					cur_read <- ""
				}
			)
			if(cur_read != ""){
				data <- paste0(c(data, cur_read), collapse="")
			}
		}

		tryCatch(close.socket(conn))
		enc2utf8(data)
	}
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
					hostname, df[1, "val"], debug=debug
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

# shared code with Rwhois and Rrdap
.vect_blacklist <- function(vect, blacklist_values=NULL){
	if(is.null(blacklist_values)){
		vect[[1]]

	} else {
		mat <- sapply(blacklist_values, FUN=function(bval){
			sapply(vect,
				FUN=function(val){
					tolower(substr(val, 1, nchar(bval))) == tolower(bval)
				}
			)
		})
		sumsMat <- rowSums(mat)
		names(sumsMat)[sumsMat==0][[1]]
	}
}

# shared code with Rwhois and Rrdap
.keyval_extract <- function(
	query_ret, keys, blacklist_values=NULL, unlist.recursive=TRUE
){
	if(is.data.frame(query_ret)){
		if(
			!is.null(query_ret[["key"]]) &&
			!is.null(query_ret[["val"]])
		){
			data_ret <- query_ret$val[tolower(query_ret$key) %in% tolower(keys)]
			.vect_blacklist(data_ret, blacklist_values)

		} else {
			NA
		}

	} else {
		data_ret <- lapply(query_ret, FUN=function(df){
			if(
				!is.null(df[["key"]]) &&
				!is.null(df[["val"]])
			){
				df$val[tolower(df$key) %in% tolower(keys)]

			} else {
				NA
			}
		})
		data_ret[sapply(data_ret, FUN=length) == 0] <- NA

		if(sum(sapply(data_ret, FUN=length) > 1) != 0){
			data_ret[sapply(data_ret, FUN=length) > 1] <-
				sapply(data_ret[
					sapply(data_ret, FUN=length) > 1],
					FUN=function(vect){
						.vect_blacklist(vect, blacklist_values)
					}
				)
		}

		unlist(data_ret, recursive=unlist.recursive)
	}
}

whois_keyextract <- .keyval_extract
whois_keyval_extract <- .keyval_extract
