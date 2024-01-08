package main

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/organizations"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/openshift/aws-account-operator/pkg/awsclient"
	"sigs.k8s.io/controller-runtime/pkg/client"
)


type CrudClient struct {
	awsclient.Client
	LoggedInUser   *iam.User
	AccountID      string
	Users          []*iam.User
	UserPolicyArns map[string][]string
	AccessKeys     []*iam.AccessKey
	Roles          []*iam.Role
	RolePolicyArns map[string][]string

	Accounts []*organizations.Account
}

func (c *CrudClient) AssumeRole(input *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {

	roleIdx := FindIndexFunc(c.Roles, func(elem *iam.Role) bool {
		return *elem.Arn == *input.RoleArn
	})

	if roleIdx == -1 {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, fmt.Sprintf("No Such Role: %s", *input.RoleArn), nil)
	}

	role := c.Roles[roleIdx]
	outArn := fmt.Sprintf("%s/%s", *input.RoleArn, *input.RoleSessionName)

	validUntil := time.Now().Add(time.Hour)
	return &sts.AssumeRoleOutput{
		AssumedRoleUser: &sts.AssumedRoleUser{
			Arn:           &outArn,
			AssumedRoleId: role.RoleId,
		},
		Credentials: &sts.Credentials{
			AccessKeyId:     aws.String("ACCESS"),
			Expiration:      &validUntil,
			SecretAccessKey: aws.String("SECRET"),
			SessionToken:    aws.String("TOKEN"),
		},
		PackedPolicySize: aws.Int64(40),
	}, nil
}

func (c *CrudClient) CreateUser(input *iam.CreateUserInput) (*iam.CreateUserOutput, error) {
	cd := time.Now()

	path := "/"
	if input.Path != nil {
		path = *input.Path
	}
	arn := fmt.Sprintf("arn:aws:iam::%s:user%s%s", c.AccountID, path, *input.UserName)

	userIdx := FindIndexFunc(c.Users, func(elem *iam.User) bool {
		return *elem.UserName == *input.UserName
	})

	if userIdx != -1 {
		return nil, awserr.New(iam.ErrCodeInvalidInputException, "", nil)
	}

	user := &iam.User{
		Arn:        &arn,
		CreateDate: &cd,
		Path:       input.Path,
		PermissionsBoundary: &iam.AttachedPermissionsBoundary{
			PermissionsBoundaryArn:  input.PermissionsBoundary,
			PermissionsBoundaryType: aws.String(iam.PermissionsBoundaryAttachmentTypePermissionsBoundaryPolicy),
		},
		Tags:     input.Tags,
		UserId:   input.UserName,
		UserName: input.UserName,
	}
	c.Users = append(c.Users, user)

	return &iam.CreateUserOutput{
		User: user,
	}, nil
}

// AttachUserPolicy implements IamIface.
func (c *CrudClient) AttachUserPolicy(input *iam.AttachUserPolicyInput) (*iam.AttachUserPolicyOutput, error) {
	if c.UserPolicyArns == nil {
		c.UserPolicyArns = map[string][]string{}
	}
	userIdx := FindIndexFunc(c.Users, func(elem *iam.User) bool {
		return *elem.UserName == *input.UserName
	})

	if userIdx == -1 {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}
	user := c.Users[userIdx]

	c.UserPolicyArns[*user.Arn] = append(c.UserPolicyArns[*user.Arn], *input.PolicyArn)
	return &iam.AttachUserPolicyOutput{}, nil
}

func (c CrudClient) GetUser(input *iam.GetUserInput) (*iam.GetUserOutput, error) {
	if input.UserName == nil {
		if c.LoggedInUser == nil {
			return nil, awserr.New("ValidationError", "Must specify userName when calling with non-User credentials", nil)
		}
		return &iam.GetUserOutput{
			User: c.LoggedInUser,
		}, nil
	}

	userIdx := FindIndexFunc(c.Users, func(elem *iam.User) bool {
		return *elem.UserName == *input.UserName
	})

	if userIdx == -1 {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	return &iam.GetUserOutput{
		User: c.Users[userIdx],
	}, nil
}

// GetRole implements IamIface.
func (c CrudClient) GetRole(input *iam.GetRoleInput) (*iam.GetRoleOutput, error) {
	roleIdx := FindIndexFunc(c.Roles, func(elem *iam.Role) bool {
		return *elem.RoleName == *input.RoleName
	})
	if roleIdx == -1 {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}
	return &iam.GetRoleOutput{
		Role: c.Roles[roleIdx],
	}, nil
}

// CreateRole implements IamIface.
func (c *CrudClient) CreateRole(input *iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
	cd := time.Now()
	path := "/"
	if input.Path != nil {
		path = *input.Path
	}
	arn := fmt.Sprintf("arn:aws:iam::%s:role%s%s", c.AccountID, path, *input.RoleName)

	roleIdx := FindIndexFunc(c.Roles, func(elem *iam.Role) bool {
		return *elem.RoleName == *input.RoleName
	})

	if roleIdx != -1 {
		return nil, awserr.New(iam.ErrCodeInvalidInputException, "", nil)
	}

	pol := &iam.Role{
		Arn:                      &arn,
		AssumeRolePolicyDocument: input.AssumeRolePolicyDocument,
		CreateDate:               &cd,
		Description:              input.Description,
		MaxSessionDuration:       input.MaxSessionDuration,
		Path:                     input.Path,
		PermissionsBoundary: &iam.AttachedPermissionsBoundary{
			PermissionsBoundaryArn:  input.PermissionsBoundary,
			PermissionsBoundaryType: aws.String(iam.PermissionsBoundaryAttachmentTypePermissionsBoundaryPolicy),
		},
		RoleId:       input.RoleName,
		RoleLastUsed: &iam.RoleLastUsed{},
		RoleName:     input.RoleName,
		Tags:         input.Tags,
	}

	c.Roles = append(c.Roles, pol)
	return &iam.CreateRoleOutput{
		Role: pol,
	}, nil
}

func (c *CrudClient) AttachRolePolicy(input *iam.AttachRolePolicyInput) (*iam.AttachRolePolicyOutput, error) {
	roleIdx := FindIndexFunc(c.Roles, func(elem *iam.Role) bool {
		return *elem.RoleName == *input.RoleName
	})
	if roleIdx == -1 {
		return &iam.AttachRolePolicyOutput{}, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}
	role := c.Roles[roleIdx]
	c.RolePolicyArns[*role.Arn] = append(c.RolePolicyArns[*role.Arn], *input.PolicyArn)
	return &iam.AttachRolePolicyOutput{}, nil
}

func (c *CrudClient) DetachRolePolicy(input *iam.DetachRolePolicyInput) (*iam.DetachRolePolicyOutput, error) {
	roleIdx := FindIndexFunc(c.Roles, func(elem *iam.Role) bool {
		return *elem.RoleName == *input.RoleName
	})
	if roleIdx == -1 {
		return &iam.DetachRolePolicyOutput{}, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}
	role := c.Roles[roleIdx]

	rolePolicyIndex := FindIndexFunc(c.RolePolicyArns[*role.Arn], func(elem string) bool {
		return elem == *input.PolicyArn
	})

	if rolePolicyIndex == -1 {
		return &iam.DetachRolePolicyOutput{}, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	c.RolePolicyArns[*role.Arn] = DeleteIndex(c.RolePolicyArns[*role.Arn], rolePolicyIndex)
	return &iam.DetachRolePolicyOutput{}, nil
}

// ListAttachedRolePolicies implements IamIface.
func (c *CrudClient) ListAttachedRolePolicies(input *iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
	roleIdx := FindIndexFunc(c.Roles, func(elem *iam.Role) bool {
		return *elem.RoleName == *input.RoleName
	})
	if roleIdx == -1 {
		return &iam.ListAttachedRolePoliciesOutput{}, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	roleArn := c.Roles[roleIdx].Arn
	policies := []*iam.AttachedPolicy{}
	for _, policyArn := range c.RolePolicyArns[*roleArn] {
		policies = append(policies, &iam.AttachedPolicy{
			PolicyArn:  &policyArn,
			PolicyName: &policyArn,
		})
	}
	return &iam.ListAttachedRolePoliciesOutput{
		AttachedPolicies: policies,
		IsTruncated:      new(bool),
		Marker:           new(string),
	}, nil
}

func (c *CrudClient) ListAccessKeys(input *iam.ListAccessKeysInput) (*iam.ListAccessKeysOutput, error) {
	accessKeys := FilterFunc(c.AccessKeys, func(elem *iam.AccessKey) bool {
		return *elem.UserName == *input.UserName
	})
	metadatas := []*iam.AccessKeyMetadata{}
	for _, ak := range accessKeys {
		metadatas = append(metadatas, &iam.AccessKeyMetadata{
			AccessKeyId: ak.AccessKeyId,
			CreateDate:  ak.CreateDate,
			Status:      ak.Status,
			UserName:    ak.UserName,
		})
	}

	return &iam.ListAccessKeysOutput{
		AccessKeyMetadata: metadatas,
		IsTruncated:       aws.Bool(false),
	}, nil
}

func (c *CrudClient) CreateAccessKey(input *iam.CreateAccessKeyInput) (*iam.CreateAccessKeyOutput, error) {
	cd := time.Now()
	ak := &iam.AccessKey{
		AccessKeyId:     aws.String("ACCESS_KEY"),
		CreateDate:      &cd,
		SecretAccessKey: aws.String("SECRET_KEY"),
		Status:          aws.String("Valid"),
		UserName:        input.UserName,
	}
	c.AccessKeys = append(c.AccessKeys, ak)
	return &iam.CreateAccessKeyOutput{
		AccessKey: ak,
	}, nil
}

func (c *CrudClient) DescribeRegions(input *ec2.DescribeRegionsInput) (*ec2.DescribeRegionsOutput, error) {
	optInErr := awserr.New("OptInRequired", "You are not subscribed to this service. Please go to http://aws.amazon.com to subscribe.", nil)
	return nil, optInErr
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

// Organizations
func (c *CrudClient) ListAccounts(input *organizations.ListAccountsInput) (*organizations.ListAccountsOutput, error) {
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

func (c *CrudClient) CreateAccount(input *organizations.CreateAccountInput) (*organizations.CreateAccountOutput, error) {
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

	c.Accounts = append(c.Accounts, acc)
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

func (c *CrudClient) DescribeCreateAccountStatus(input *organizations.DescribeCreateAccountStatusInput) (*organizations.DescribeCreateAccountStatusOutput, error) {
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

func (c *CrudClient) MoveAccount(input *organizations.MoveAccountInput) (*organizations.MoveAccountOutput, error) {
	return &organizations.MoveAccountOutput{}, nil
}

type TreeNode[T interface{}] struct {
	Parent   *TreeNode[T]
	Children []*TreeNode[T]
	Content  T
}

func (c *CrudClient) CreateOrganizationalUnit(input *organizations.CreateOrganizationalUnitInput) (*organizations.CreateOrganizationalUnitOutput, error) {
	ou := &organizations.OrganizationalUnit{
		Arn:  new(string),
		Id:   new(string),
		Name: new(string),
	}

	return &organizations.CreateOrganizationalUnitOutput{
		OrganizationalUnit: ou,
	}, nil
}
// func (c *CrudClient) ListOrganizationalUnitsForParent(input *organizations.ListOrganizationalUnitsForParentInput) (*organizations.ListOrganizationalUnitsForParentOutput, error)
// func (c *CrudClient) ListChildren(input *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error)
// func (c *CrudClient) TagResource(input *organizations.TagResourceInput) (*organizations.TagResourceOutput, error)
// func (c *CrudClient) UntagResource(input *organizations.UntagResourceInput) (*organizations.UntagResourceOutput, error)
// func (c *CrudClient) ListParents(input *organizations.ListParentsInput) (*organizations.ListParentsOutput, error)
// func (c *CrudClient) ListTagsForResource(input *organizations.ListTagsForResourceInput) (*organizations.ListTagsForResourceOutput, error)
