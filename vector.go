package privacy

import (
    "errors"
)

type Vector struct {
    container []string
    capacity  int
}

func NewVector(size int) *Vector {
    return &Vector{make([]string, size), size}
}

func (v *Vector) Append(str string) {
    if len(v.container) == v.capacity {
        newContainer := make([]string, len(v.container), (cap(v.container)*2))
        copy(newContainer, v.container)
        v.container = newContainer
    }
    v.container = append(v.container, str)
}

func (v *Vector) At(index int) (string, error) {
    if index < len(v.container) {
        return v.container[index], nil
    }

    return "", errors.New("Index out of bounds")
}

func (v *Vector) Size() int {
    return len(v.container)
}
