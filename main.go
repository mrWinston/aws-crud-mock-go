package main

import (
	"fmt"

	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
)

func main(){
  fmt.Println("hello")
  var iamc iamiface.IAMAPI

  iamc = &IamClient{}
  iamc.CreateGroup(&iam.CreateGroupInput{})
   
}

