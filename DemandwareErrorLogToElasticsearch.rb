input {
  file {
    #path => "C:/Users/cmagnuson/Desktop/DemandwareLogs/customerror-blade2-2-appserver-*.log"
	#path => "C:/Users/cmagnuson/Desktop/DemandwareLogs/error-*.log"
	#path => "C:/Users/cmagnuson/Desktop/DemandwareLogs/error-blade0-0-appserver-20160329.log"
	path => "C:\Users\cmagnuson\DemandwareLogs\error-blade0-0-appserver-20160329-sample.log"
    type => "error"
    tags => "production"
	start_position => "beginning"
	sincedb_path => "NUL"
    codec => multiline {
        pattern => "\A\[%{TIMESTAMP_ISO8601:demandware_timestamp} GMT\]"
        negate => true
        what => previous
    }
  }
}

filter {
    grok {
        match => { "message" => "\A\[%{TIMESTAMP_ISO8601:demandware_timestamp} GMT\]" }
    }
    date {
        match => ["demandware_timestamp", "YYYY-MM-dd HH:mm:ss.SSS"]
    }
	
	grok {
        match => { "path" => "^.*[\/\\](?<FileNameWithoutExtension>.*)\.(.*)$" }	
	}
	
	grok {
		match => { "FileNameWithoutExtension" => "\A%{WORD:LogFileType}-(?<LogFileBlade>[[:alpha:]]+[[:digit:]]-[[:digit:]])-%{WORD:LogFileBladeRole}-%{YEAR:LogFileYear}%{MONTHNUM:LogFileMonth}%{MONTHDAY:LogFileDay}"}
	}
	
    grok {
        break_on_match => false
        match => [ "message", "\[[0-9\:\s\.\-A-Z]+\]\s%{WORD:LoggerLevel}\s%{WORD:servlet}\|%{NUMBER:idk}\|%{DATA:sitename}\|%{DATA:action}\|%{WORD:pipeline}\|%{DATA:sessionid} %{DATA:ExceptionClass}\s\s\-\s%{DATA:sitename}\s%{WORD:ExceptionType}\s%{WORD:storefront}\s%{DATA:sessionid}\s%{DATA:random}\s%{DATA:alsorandom}\s%{GREEDYDATA:short_message}" ]
        match => [ "message", "\[[0-9\:\s\.\-A-Z]+\]\s%{WORD:LoggerLevel}\s%{WORD:servlet}\|%{NUMBER:idk}\|%{DATA:sitename}\|%{DATA:action}\|%{WORD:pipeline}\|%{DATA:sessionid} %{DATA:ExceptionClass} %{GREEDYDATA:short_message}" ]
    }
	grok {
		match => [ "message", "(?<SectionWtihKeyValues>System Information(.|\r|\n)*\z)"]
	} 
	kv {
		source => "SectionWtihKeyValues"
		field_split => "\r\n"
		trim => " "
		value_split => ":="
		remove_field => ["SectionWtihKeyValues"]
	}
}
output {
	stdout { codec => rubydebug }
	#elasticsearch {
    #    host => "localhost"
    #    port => 9300
    #    index => "logstash-demandware-error-%{+YYYY.MM}"
    #    document_id => "%{demandware_timestamp}%{FileNameWithoutExtension}"
	#}
  
}