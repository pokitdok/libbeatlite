/*
Example beat using libbeatlite. Reads lines from stdin, sends them to
elasticsearch, uses config file.
*/
package main

import (
	"bufio"
	"log"
	"os"

	"github.com/pokitdok/libbeatlite"
)

func main() {

	libbeatlite.DEBUG = true

	c := &libbeatlite.Client{
		URL:  "http://localhost:9200",
		Name: "consolebeatlite",
	}

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		s := map[string]interface{}{"message": line}
		m := &libbeatlite.Message{Source: s}
		_, err := c.Send(m)
		if err != nil {
			log.Println(err)
		}
	}

	return
}
