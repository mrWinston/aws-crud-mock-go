package goawscrudclient

import (
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iam"
)

func TestAllStore_GetThingByArn(t *testing.T) {
  store := &AllStore{
    all: []interface{}{},
  }
  
  user := iam.User{
    Arn: aws.String("userraw"),
  }
  store.PutThing(user)

  userPtr := &iam.User{
    Arn: aws.String("userptr"),
  }
  store.PutThing(userPtr)

  role := iam.Role{
    Arn: aws.String("roleraw"),
  }
  store.PutThing(role)

  rolePtr := &iam.Role{
    Arn: aws.String("roleptr"),
  }
  store.PutThing(rolePtr)


  var newUser iam.User = store.GetThingByArn("userraw").(iam.User)
  if ! reflect.DeepEqual(newUser, user) {
    t.Errorf("Retrieved user not the same, want: %v , got %v", user, newUser)
  }

  var newUserPtr *iam.User = store.GetThingByArn("userptr").(*iam.User)
  if newUserPtr != userPtr {
    t.Errorf("Retrieved user pointers not the same, want: %v , got %v", user, newUser)
  }
}
