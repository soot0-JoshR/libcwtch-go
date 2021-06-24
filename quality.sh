#!/bin/sh

echo "Checking code quality (you want to see no output here)"
echo ""

echo "Vetting:"
go list ./... | xargs go vet

echo ""
echo "Linting:"

go list ./... | xargs golint


echo "Time to format"
gofmt -l -s -w .

# ineffassign (https://github.com/gordonklaus/ineffassign)
echo "Checking for ineffectual assignment of errors (unchecked errors...)"
ineffassign .

# misspell (https://github.com/client9/misspell/cmd/misspell)
echo "Checking for misspelled words..."
misspell . | grep -v "vendor/" | grep -v "go.sum" | grep -v ".idea"
