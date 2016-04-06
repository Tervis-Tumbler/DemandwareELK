input {
    file {
        #path => "C:/Users/username/Desktop/DemandwareLogs/error-*.log"
        path => "$LogstashFilePathValue"
        type => "DemandwareError"
        tags => "$EnvironmentName"
        start_position => "beginning"
        ignore_older => 99999999
        sincedb_path => "NUL"
        codec => multiline {
            pattern => "\A\[%{TIMESTAMP_ISO8601:demandware_timestamp} GMT\]"
            negate => true
            what => previous
            auto_flush_interval => 10
            max_lines => 9999
        }
    }
}

filter {
    grok {
        match => { "message" => "\A\[%{TIMESTAMP_ISO8601:demandware_timestamp} GMT\]" }
    }
    date {
        match => ["demandware_timestamp", "YYYY-MM-dd HH:mm:ss.SSS"]
        timezone => "UTC"
    }
    
    grok {
        match => { "path" => "^.*[\/\\](?<FileNameWithoutExtension>.*)\.(.*)$" }    
    }
    
    grok {
        match => { "FileNameWithoutExtension" => "\A%{WORD:LogFileType}-(?<LogFileBlade>[[:alpha:]]+[[:digit:]]-[[:digit:]])-%{WORD:LogFileBladeRole}-%{YEAR:LogFileYear}%{MONTHNUM:LogFileMonth}%{MONTHDAY:LogFileDay}"}
    }
    
    mutate {
        add_field => {"UnparsedMessage" => "%{message}"}
        add_field => {"MessageHash" => "%{message}"}
    }
    
    grok {
        match => {"UnparsedMessage" => "(?<StackTrace>\nStack trace <(.|\r|\n)*)"}
        tag_on_failure => []
    }
    if [StackTrace] {
        #mutate { gsub => [ "UnparsedMessage", "%{StackTrace}", ""]} #not sure why this doesn't work but it doesn't, try again later
        mutate { gsub => [ "UnparsedMessage", "\nStack trace <(.|\r|\n)*", ""]}
    }
    
    grok {
        match => [ "UnparsedMessage", "(?<SectionWtihKeyValues>\nSystem Information(.|\r|\n)*)"]
    }
    if [SectionWtihKeyValues] {
        #mutate { gsub => [ "UnparsedMessage", "%{SectionWtihKeyValues}", ""]}
        mutate { gsub => [ "UnparsedMessage", "\nSystem Information(.|\r|\n)*", ""]}
        kv {
            source => "SectionWtihKeyValues"
            field_split => "\r\n"
            trim => " "
            value_split => ":="
            remove_field => ["SectionWtihKeyValues"]
        }
    }

    grok {
        break_on_match => false
        match => [ "UnparsedMessage", "\[[0-9\:\s\.\-A-Z]+\]\s%{WORD:LoggerLevel}\s%{WORD:servlet}\|%{NUMBER:idk}\|%{DATA:sitename}\|%{DATA:action}\|%{WORD:pipeline}\|%{DATA:sessionid} %{DATA:ExceptionClass}\s\s\-\s%{DATA:sitename}\s%{WORD:ExceptionType}\s%{WORD:storefront}\s%{DATA:sessionid}\s%{DATA:random}\s%{DATA:alsorandom}\s%{GREEDYDATA:short_message}" ]
        match => [ "UnparsedMessage", "\[[0-9\:\s\.\-A-Z]+\]\s%{WORD:LoggerLevel}\s%{WORD:servlet}\|%{NUMBER:idk}\|%{DATA:sitename}\|%{DATA:action}\|%{WORD:pipeline}\|%{DATA:sessionid} %{DATA:ExceptionClass} %{GREEDYDATA:short_message}" ]
    }
    
    #if [demandware_timestamp] {
    #    mutate {
    #        add_field => { "ElasticSearchDocumentID" => "%{demandware_timestamp}%{FileNameWithoutExtension}" }
    #    }
    #} else {
    #     mutate {
    #        add_field => { "ElasticSearchDocumentID" => "%{@timestamp}%{FileNameWithoutExtension}"}
    #    }   
    #}
    
    anonymize {
        algorithm => "SHA1"
        fields => ["MessageHash"]
        key => ""
    }
}
output {
$(
if ($Development) {@"
    stdout { codec => rubydebug }
"@
} else { @"
    elasticsearch {
        hosts => localhost
        index => "logstash-demandware-error-%{+YYYY.MM}"
        document_id => "%{MessageHash}"
    }
"@
}
)
}