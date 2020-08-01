package main

type A interface {
	a()
}

type B interface {
	b(a A)
}

type A1 struct {
	a1 uint8
}

func (a *A1) a() {}

type B1 struct {
	b1 uint8
}

func (b *B1) b(a *A1) {}

func main() {
	c := make(map[A]bool)
	c[&A1{8}] = true

	return
}
