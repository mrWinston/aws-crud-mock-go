package main

import (
	"github.com/google/go-cmp/cmp"
)

func FindIndex[T any](o []T, element T) int {
	for i, v := range o {
		if cmp.Equal(v, element) {
			return i
		}
	}
	return -1
}

func FindIndexFunc[T any](o []T, compareFunc func(elem T)bool) int {
	for i, v := range o {
		if compareFunc(v) {
			return i
		}
	}
	return -1
}

func FilterFunc[T any](o []T, compareFunc func(elem T) bool) []T {
  newArray := []T{}

  for _, v := range o {
    if compareFunc(v) {
      newArray = append(newArray, v)
    }
  }

  return newArray
}

func DeleteIndex[T any](o []T, idx int) []T {
	newArray := o
	newArray[idx] = newArray[len(newArray)-1]
	return newArray[:len(newArray)-1]
}
