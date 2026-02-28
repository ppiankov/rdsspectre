package logging

import "testing"

func TestInit(t *testing.T) {
	Init(false)
	Init(true)
}
