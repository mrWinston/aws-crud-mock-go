package goawscrudclient

import (
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/support"
	"github.com/aws/aws-sdk-go/service/support/supportiface"
	"github.com/timshannon/badgerhold/v4"
)

type SupportCrud struct {
  supportiface.SupportAPI
}


func NewCaseId() string {
  return fmt.Sprintf("case-%s", NewRandomId())
}

func (c *SupportCrud) CreateCase(input *support.CreateCaseInput) (*support.CreateCaseOutput, error) {
  caseId := NewCaseId()

  newCase := support.CaseDetails{
  	CaseId:               &caseId,
  	CategoryCode:         input.CategoryCode,
  	CcEmailAddresses:     input.CcEmailAddresses,
  	DisplayId:            &caseId,
  	Language:             input.Language,
  	ServiceCode:          input.ServiceCode,
  	SeverityCode:         input.SeverityCode,
  	Status:               aws.String("resolved"),
  	Subject:              input.Subject,
  	SubmittedBy:          aws.String("todo@example.com"),
  	TimeCreated:          aws.String(time.Now().UTC().Format(time.RFC3339)),
  }

  err := BH().Insert(caseId, &newCase)
  if err != nil {
    return nil, err
  }

  return &support.CreateCaseOutput{
  	CaseId: &caseId,
  }, nil
}


func (c *SupportCrud) DescribeCases(input *support.DescribeCasesInput) (*support.DescribeCasesOutput, error) {

  cases := []*support.CaseDetails{}
  
  caseIdsBadger := []interface{}{}

  for _, v := range input.CaseIdList {
    caseIdsBadger = append(caseIdsBadger, v)
  }

  err := BH().Find(&cases, badgerhold.Where("CaseId").In(caseIdsBadger...))

  if err != nil {
    return nil, err
  }

  return &support.DescribeCasesOutput{
  	Cases:     cases,
  },nil
}
	
