package service

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/organizations"
	"github.com/aws/aws-sdk-go/service/organizations/organizationsiface"
)


type OrganizationsCrud struct {
  organizationsiface.OrganizationsAPI
  Accountid string
}


// Organizations
func (c *OrganizationsCrud) ListAccounts(input *organizations.ListAccountsInput) (*organizations.ListAccountsOutput, error) {
	return &organizations.ListAccountsOutput{
		Accounts: c.Accounts,
	}, nil
}

func GenerateAccountArn(accountID string, accountName string) string {
	return fmt.Sprintf("arn:aws:organizations::%[1]s:account/%[2]s/%[1]s", accountID, accountName)
}

func GenerateAccountId() string {
	num := rand.Int63()
	num = num%900000000000 + 100000000000
	return fmt.Sprintf("%d", num)
}

func (c *OrganizationsCrud) CreateAccount(input *organizations.CreateAccountInput) (*organizations.CreateAccountOutput, error) {
	accountId := GenerateAccountId()
	accountArn := GenerateAccountArn(accountId, *input.AccountName)
	acc := &organizations.Account{
		Arn:             &accountArn,
		Email:           input.Email,
		Id:              &accountId,
		JoinedMethod:    aws.String("CREATED"),
		JoinedTimestamp: aws.Time(time.Now()),
		Name:            input.AccountName,
		Status:          aws.String("ACTIVE"),
	}
  allStore.PutThing(acc)
	cao := &organizations.CreateAccountOutput{
		CreateAccountStatus: &organizations.CreateAccountStatus{
			AccountId:          acc.Id,
			AccountName:        acc.Name,
			Id:                 aws.String(fmt.Sprintf("car-%s", *acc.Id)),
			RequestedTimestamp: acc.JoinedTimestamp,
			State:              aws.String("IN_PROGRESS"),
		},
	}
	return cao, nil
}

func (c *OrganizationsCrud) DescribeCreateAccountStatus(input *organizations.DescribeCreateAccountStatusInput) (*organizations.DescribeCreateAccountStatusOutput, error) {
	accountId := strings.TrimPrefix(*input.CreateAccountRequestId, "car-")
	accountIndex := FindIndexFunc(c.Accounts, func(elem *organizations.Account) bool {
		return *elem.Id == accountId
	})
	if accountIndex == -1 {
		return nil, awserr.New("CreateAccountStatusNotFoundException", "We can't find an create account request with the CreateAccountRequestId that you specified.", nil)
	}

	account := c.Accounts[accountIndex]
	car := &organizations.CreateAccountStatus{
		AccountId:          account.Id,
		AccountName:        account.Name,
		CompletedTimestamp: aws.Time(time.Now()),
		Id:                 input.CreateAccountRequestId,
		RequestedTimestamp: account.JoinedTimestamp,
		State:              aws.String("SUCCEEDED"),
	}

	return &organizations.DescribeCreateAccountStatusOutput{
		CreateAccountStatus: car,
	}, nil
}

func (c *OrganizationsCrud) MoveAccount(input *organizations.MoveAccountInput) (*organizations.MoveAccountOutput, error) {
	return &organizations.MoveAccountOutput{}, nil
}

type TreeNode[T interface{}] struct {
	Parent   *TreeNode[T]
	Children []*TreeNode[T]
	Content  T
}

func (c *OrganizationsCrud) CreateOrganizationalUnit(input *organizations.CreateOrganizationalUnitInput) (*organizations.CreateOrganizationalUnitOutput, error) {
	ou := &organizations.OrganizationalUnit{
		Arn:  new(string),
		Id:   new(string),
		Name: new(string),
	}

	return &organizations.CreateOrganizationalUnitOutput{
		OrganizationalUnit: ou,
	}, nil
}
