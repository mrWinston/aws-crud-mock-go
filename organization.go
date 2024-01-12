package goawscrudclient

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/organizations"
	"github.com/aws/aws-sdk-go/service/organizations/organizationsiface"
	"github.com/timshannon/badgerhold/v4"
)

type OrganizationsCrud struct {
	organizationsiface.OrganizationsAPI
	Accountid string
  RootOUId string
}

// Organizations
func (c *OrganizationsCrud) ListAccounts(input *organizations.ListAccountsInput) (*organizations.ListAccountsOutput, error) {
	accounts := []*organizations.Account{}
	err := BH().Find(&accounts, nil)

	if err != nil {
		return nil, awserr.New(organizations.ErrCodeInvalidInputException, "", nil)
	}
	return &organizations.ListAccountsOutput{
		Accounts: accounts,
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
		JoinedTimestamp: aws.Time(time.Now().UTC()),
		Name:            input.AccountName,
		Status:          aws.String("ACTIVE"),
	}


  err := BH().Insert(acc.Id, acc)

  if err != nil {
    return nil, err
  }

  err = BH().Insert(badgerhold.NextSequence(), TreeMapper{
  	Parent: c.RootOUId,
  	Child:  accountId,
  })

  if err != nil {
    return nil, err
  }

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
	account := &organizations.Account{}
	err := BH().Get(accountId, account)

	if err != nil {
		return nil, awserr.New(organizations.ErrCodeInvalidInputException, "", nil)
	}

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

type TreeMapper struct {
	Parent string
	Child  string
}

func (c *OrganizationsCrud) MoveAccount(input *organizations.MoveAccountInput) (*organizations.MoveAccountOutput, error) {
	oldMapper := &TreeMapper{}
	_ = BH().DeleteMatching(oldMapper, badgerhold.Where("Parent").Eq(input.SourceParentId).And("Child").Eq(input.AccountId))

	_ = BH().Insert(badgerhold.NextSequence(), TreeMapper{
		Parent: *input.DestinationParentId,
		Child:  *input.AccountId,
	})

	return &organizations.MoveAccountOutput{}, nil
}

func GenerateOUArn(accountId string, ouId string, orgId string) string {
	return fmt.Sprintf("arn:aws:organizations::%s:ou/%s/%s", accountId, orgId, ouId)
}

func GenerateOUId() string {
	num := rand.Int63()
	num = num%900000000000 + 100000000000
	return fmt.Sprintf("ou-%d", num)
}

func (c *OrganizationsCrud) CreateOrganizationalUnit(input *organizations.CreateOrganizationalUnitInput) (*organizations.CreateOrganizationalUnitOutput, error) {
	ouId := GenerateOUId()
	ouArn := GenerateOUArn(c.Accountid, ouId, "000000000")

	ou := &organizations.OrganizationalUnit{
		Arn:  aws.String(ouArn),
		Id:   aws.String(ouId),
		Name: input.Name,
	}

	err := BH().Insert(ou.Id, ou)
	if err != nil {
		return nil, awserr.New(organizations.ErrCodeInvalidInputException, "", err)
	}

	err = BH().Insert(badgerhold.NextSequence(), TreeMapper{
		Parent: *input.ParentId,
		Child:  *ou.Id,
	})
	if err != nil {
		return nil, awserr.New(organizations.ErrCodeInvalidInputException, "", err)
	}

	return &organizations.CreateOrganizationalUnitOutput{
		OrganizationalUnit: ou,
	}, nil
}

func (c *OrganizationsCrud) ListOrganizationalUnitsForParent(input *organizations.ListOrganizationalUnitsForParentInput) (*organizations.ListOrganizationalUnitsForParentOutput, error) {
	tms := []TreeMapper{}

	err := BH().Find(&tms, badgerhold.Where("Parent").Eq(input.ParentId))
	if err != nil {
		return nil, awserr.New(organizations.ErrCodeInvalidInputException, "", err)
	}

	ous := []*organizations.OrganizationalUnit{}

	for _, tm := range tms {
		ou := &organizations.OrganizationalUnit{}
		err := BH().Get(tm.Child, ou)
		if err != nil {
			continue
		}
		ous = append(ous, ou)
	}

	return &organizations.ListOrganizationalUnitsForParentOutput{
		OrganizationalUnits: ous,
	}, nil
}

func (c *OrganizationsCrud) ListChildren(input *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error) {
	children := []*organizations.Child{}

	treeMappers := []TreeMapper{}
	err := BH().Find(&treeMappers, badgerhold.Where("Parent").Eq(input.ParentId))
	if err != nil {
		return nil, awserr.New(organizations.ErrCodeInvalidInputException, "", err)
	}

	for _, tm := range treeMappers {
		if *input.ChildType == organizations.ChildTypeAccount {
			if !strings.HasPrefix(tm.Child, "ou-") {
				children = append(children, &organizations.Child{
					Id:   &tm.Child,
					Type: input.ChildType,
				})
			}
		} else {
			if strings.HasPrefix(tm.Child, "ou-") {
				children = append(children, &organizations.Child{
					Id:   &tm.Child,
					Type: input.ChildType,
				})
			}
		}

	}

	return &organizations.ListChildrenOutput{
		Children: children,
	}, nil
}

type TagMapper struct {
	Target string
	Tag    *organizations.Tag
}

func (c *OrganizationsCrud) TagResource(input *organizations.TagResourceInput) (*organizations.TagResourceOutput, error) {

	for _, t := range input.Tags {
		err := BH().Insert(badgerhold.NextSequence(), TagMapper{
			Target: *input.ResourceId,
			Tag:    t,
		})
		if err != nil {
			return nil, awserr.New(organizations.ErrCodeInvalidInputException, "", err)
		}
	}

	return &organizations.TagResourceOutput{}, nil
}

func (c *OrganizationsCrud) UntagResource(input *organizations.UntagResourceInput) (*organizations.UntagResourceOutput, error) {
	tm := &TagMapper{}
	for _, v := range input.TagKeys {
		err := BH().DeleteMatching(tm, badgerhold.Where("Target").Eq(input.ResourceId).And("Tag.Key").Eq(v))
		if err != nil {
			return nil, awserr.New(organizations.ErrCodeInvalidInputException, "", err)
		}
	}

	return &organizations.UntagResourceOutput{}, nil
}

func (c *OrganizationsCrud) ListParents(input *organizations.ListParentsInput) (*organizations.ListParentsOutput, error) {
	tm := TreeMapper{}
	err := BH().FindOne(&tm, badgerhold.Where("Child").Eq(input.ChildId))
	if err != nil {
		return nil, awserr.New(organizations.ErrCodeInvalidInputException, "", err)
	}

  var parentType string
  if strings.HasPrefix(tm.Parent ,"ou") {
    parentType = organizations.ParentTypeOrganizationalUnit
  } else {
    parentType = organizations.ParentTypeRoot
  }

	return &organizations.ListParentsOutput{
		Parents: []*organizations.Parent{{
			Id:   &tm.Parent,
			Type: &parentType,
		}},
	}, nil
}

func (c *OrganizationsCrud) ListTagsForResource(input *organizations.ListTagsForResourceInput) (*organizations.ListTagsForResourceOutput, error) {
  tm := []TagMapper{}

  err := BH().Find(&tm, badgerhold.Where("Target").Eq(input.ResourceId))
	if err != nil {
		return nil, awserr.New(organizations.ErrCodeInvalidInputException, "", err)
	}

  tags := []*organizations.Tag{}
  for _, t := range tm {
    if t.Tag.Value == nil {
      t.Tag.Value = aws.String("")
    }
    tags = append(tags, t.Tag)
  } 
  
  return &organizations.ListTagsForResourceOutput{
  	Tags:      tags,
  }, nil

}
