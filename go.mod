module github.com/test/vulnerability-scanner

go 1.21

// Testing all 3 vulnerability scanners with vulnerable packages
require (
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	golang.org/x/text v0.3.2
	gopkg.in/yaml.v2 v2.2.7
)
