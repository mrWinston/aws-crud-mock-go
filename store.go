package goawscrudclient

import (
	"fmt"

	"github.com/timshannon/badgerhold/v4"
)

var bh *badgerhold.Store

type RegionMapping struct {
  Region string
  Key interface{}
}

func BH() *badgerhold.Store {
  if bh == nil {
    bhOpts := badgerhold.DefaultOptions
    bhOpts.Options.InMemory = true
    var err error
    bh, err = badgerhold.Open(bhOpts)
    if err != nil {
      panic(fmt.Sprintf("Got an error initializing badger: %v", err))
    }
  }

  return bh
}

type RegionMapper struct {
  Region string
  Data interface{}
}

func InsertWithRegion(key interface{}, data interface{}, region string) {
  newRegionMapper := RegionMapper{
    Region: region,
    Data: data,
  }

  BH().Insert(key, newRegionMapper)
}
