package service

import (
	"reflect"

	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/google/go-cmp/cmp"
)

type CrudClientStore struct {
	Users                []*iam.User
	UserAttachedPolicies map[string][]string
	UserInlinePolicies   map[string]map[string]*string
	AccessKeys           []*iam.AccessKey
	Policies             []*iam.Policy
	PolicyVersions       map[string][]*iam.PolicyVersion
	Roles                []*iam.Role
	RoleAttachedPolicies map[string][]string
}

var ClientStore *CrudClientStore = &CrudClientStore{
	Users:                []*iam.User{},
	UserAttachedPolicies: map[string][]string{},
	UserInlinePolicies:   map[string]map[string]*string{},
	AccessKeys:           []*iam.AccessKey{},
	Policies:             []*iam.Policy{},
	PolicyVersions:       map[string][]*iam.PolicyVersion{},
	Roles:                []*iam.Role{},
	RoleAttachedPolicies: map[string][]string{},
}

func (c *CrudClientStore) getRoleByName(name string) *iam.Role {
	for _, r := range c.Roles {
		if name == *r.RoleName {
			return r
		}
	}
	return nil
}
func (c *CrudClientStore) getUserByName(name string) *iam.User {
	for _, u := range c.Users {
		if name == *u.UserName {
			return u
		}
	}
	return nil
}

func FindIndex[T any](o []T, element T) int {
	for i, v := range o {
		if cmp.Equal(v, element) {
			return i
		}
	}
	return -1
}

func FindIndexFunc[T any](o []T, compareFunc func(elem T) bool) int {
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

type AllStore struct {
	all []interface{}
}

var allStore *AllStore = &AllStore{
	all: []interface{}{},
}

func (a *AllStore) PutThing(thing interface{}) {
	a.all = append(a.all, thing)
}

func (a *AllStore) GetThingByArn(arn string) interface{} {
	for _, v := range a.all {
		elementVal := reflect.Indirect(reflect.ValueOf(v))
		if elementVal.Kind() != reflect.Struct {
			continue
		}
		arnField := elementVal.FieldByName("Arn")
		if arnField.IsZero() {
			continue
		}
		arnField = reflect.Indirect(arnField)
		switch arnField.Kind() {
		case reflect.String:
			if arn == arnField.String() {
				return v
			}
		}
	}

	return nil
}

func (a *AllStore) GetThingByFieldName(fieldName string, fieldValue string) interface{} {
  idx := a.searchForIndexByFieldName(fieldName, fieldValue)

  if idx == -1 {
    return nil
  }
	return a.all[idx]
}

func (a *AllStore) GetThingByFieldNameAndType(fieldName string, fieldValue string, targetType reflect.Type) interface{} {
  idxs := a.ListAllIdxByFieldName(fieldName, fieldValue)

  for _, v := range idxs {
    if reflect.TypeOf(a.all[v]) == targetType {
      return a.all[v]
    }
  }
	return nil
}

func (a *AllStore) GetAllThingsByType(targetType reflect.Type) []interface{} {
  allThings := []interface{}{}
  for _, v := range(a.all) {
    if reflect.TypeOf(v) == targetType {
      allThings = append(allThings, v)
    }
  }

  return allThings
}

func (a *AllStore) GetAllThingsByFieldName(fieldName string, fieldValue string) []interface{} {
  elements := []interface{}{}
  idxs := a.ListAllIdxByFieldName(fieldName, fieldValue)

  for _, idx := range(idxs) {
    elements = append(elements, a.all[idx])
  }
	return elements
}

func (a *AllStore) RemoveThingByFieldName(fieldName string, fieldValue string) interface{} {
  idx := a.searchForIndexByFieldName(fieldName, fieldValue)
  if idx == -1 {
    return nil
  }
  
  return a.RemoveThingByIdx(idx)
}

func (a *AllStore) RemoveThingByArn(arn string) interface{} {
  idx := a.searchForIndexByFieldName("Arn", arn)
  if idx == -1 {
    return nil
  }
  
  return a.RemoveThingByIdx(idx)
}

func (a *AllStore) RemoveAllThingsByFieldName(fieldName string, fieldValue string) {
  for _, idx := range a.ListAllIdxByFieldName(fieldName, fieldValue) {
    a.RemoveThingByIdx(idx)
  }
}

func (a *AllStore) RemoveThingByIdx(idx int) interface{} {
  element := a.all[idx]

  a.all[idx] = a.all[len(a.all) - 1]
  a.all = a.all[:len(a.all) - 1]

  return element
}

func (a *AllStore) ListAllIdxByFieldName(fieldName string, fieldValue string) []int {
  idxs := []int{}

	for i, v := range a.all {
		elementVal := reflect.Indirect(reflect.ValueOf(v))
		if elementVal.Kind() != reflect.Struct {
			continue
		}
		arnField := elementVal.FieldByName(fieldName)
		if arnField.IsZero() {
			continue
		}
		arnField = reflect.Indirect(arnField)
		switch arnField.Kind() {
		case reflect.String:
			if fieldValue == arnField.String() {
        idxs = append(idxs, i)
			}
		}
	}
  return idxs
}

func (a *AllStore) searchForIndexByFieldName(fieldName string, fieldValue string) int {
	for i, v := range a.all {
		elementVal := reflect.Indirect(reflect.ValueOf(v))
		if elementVal.Kind() != reflect.Struct {
			continue
		}
		arnField := elementVal.FieldByName(fieldName)
		if arnField.IsZero() {
			continue
		}
		arnField = reflect.Indirect(arnField)
		switch arnField.Kind() {
		case reflect.String:
			if fieldValue == arnField.String() {
				return i
			}
		}
	}

	return -1
}
