package main

import (
	"fmt"
	"time"
"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
)

type IamIface interface {
	//IAM
	CreateAccessKey(*iam.CreateAccessKeyInput) (*iam.CreateAccessKeyOutput, error)
	CreateUser(*iam.CreateUserInput) (*iam.CreateUserOutput, error)
	DeleteAccessKey(*iam.DeleteAccessKeyInput) (*iam.DeleteAccessKeyOutput, error)
	DeleteUser(*iam.DeleteUserInput) (*iam.DeleteUserOutput, error)
	DeleteUserPolicy(*iam.DeleteUserPolicyInput) (*iam.DeleteUserPolicyOutput, error)
	GetUser(*iam.GetUserInput) (*iam.GetUserOutput, error)
	ListUsers(*iam.ListUsersInput) (*iam.ListUsersOutput, error)
	ListUsersPages(*iam.ListUsersInput, func(*iam.ListUsersOutput, bool) bool) error
	ListUserTags(*iam.ListUserTagsInput) (*iam.ListUserTagsOutput, error)
	ListAccessKeys(*iam.ListAccessKeysInput) (*iam.ListAccessKeysOutput, error)
	ListUserPolicies(*iam.ListUserPoliciesInput) (*iam.ListUserPoliciesOutput, error)
	PutUserPolicy(*iam.PutUserPolicyInput) (*iam.PutUserPolicyOutput, error)
	AttachUserPolicy(*iam.AttachUserPolicyInput) (*iam.AttachUserPolicyOutput, error)
	DetachUserPolicy(*iam.DetachUserPolicyInput) (*iam.DetachUserPolicyOutput, error)
	ListPolicies(*iam.ListPoliciesInput) (*iam.ListPoliciesOutput, error)
	ListAttachedUserPolicies(*iam.ListAttachedUserPoliciesInput) (*iam.ListAttachedUserPoliciesOutput, error)
	CreatePolicy(*iam.CreatePolicyInput) (*iam.CreatePolicyOutput, error)
	DeletePolicy(input *iam.DeletePolicyInput) (*iam.DeletePolicyOutput, error)
	DeletePolicyVersion(input *iam.DeletePolicyVersionInput) (*iam.DeletePolicyVersionOutput, error)
	GetPolicy(input *iam.GetPolicyInput) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(input *iam.GetPolicyVersionInput) (*iam.GetPolicyVersionOutput, error)
	ListPolicyVersions(input *iam.ListPolicyVersionsInput) (*iam.ListPolicyVersionsOutput, error)
	AttachRolePolicy(*iam.AttachRolePolicyInput) (*iam.AttachRolePolicyOutput, error)
	DetachRolePolicy(*iam.DetachRolePolicyInput) (*iam.DetachRolePolicyOutput, error)
	ListAttachedRolePolicies(*iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error)
	CreateRole(*iam.CreateRoleInput) (*iam.CreateRoleOutput, error)
	GetRole(*iam.GetRoleInput) (*iam.GetRoleOutput, error)
	DeleteRole(*iam.DeleteRoleInput) (*iam.DeleteRoleOutput, error)
	ListRoles(input *iam.ListRolesInput) (*iam.ListRolesOutput, error)
}

type IamClient struct {
  iamiface.IAMAPI
	users          []*iam.User
	userPolicyArns map[string][]string
	// map from username to a map of policy name to policy document
	userInlinePolicies map[string]map[string]*string
	accessKeys         []*iam.AccessKey
	policies           []*iam.Policy
	policyVersions     map[string][]*iam.PolicyVersion
	roles              []*iam.Role
	rolePolicyArns     map[string][]string
	accountid          string
}


func (c *IamClient) getRoleByName(name string) *iam.Role {
	for _, r := range c.roles {
		if name == *r.RoleName {
			return r
		}
	}
	return nil
}
func (c *IamClient) getUserByName(name string) *iam.User {
	for _, u := range c.users {
		if name == *u.UserName {
			return u
		}
	}
	return nil
}

// AttachRolePolicy implements IamIface.
func (c *IamClient) AttachRolePolicy(input *iam.AttachRolePolicyInput) (*iam.AttachRolePolicyOutput, error) {
	role := c.getRoleByName(*input.RoleName)
	if role == nil {
		return &iam.AttachRolePolicyOutput{}, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}
	c.rolePolicyArns[*role.Arn] = append(c.rolePolicyArns[*role.Arn], *input.PolicyArn)
	return &iam.AttachRolePolicyOutput{}, nil
}

// AttachUserPolicy implements IamIface.
func (c *IamClient) AttachUserPolicy(input *iam.AttachUserPolicyInput) (*iam.AttachUserPolicyOutput, error) {
	user := c.getUserByName(*input.UserName)
	if user == nil {
		return &iam.AttachUserPolicyOutput{}, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}
	c.userPolicyArns[*user.Arn] = append(c.userPolicyArns[*user.Arn], *input.PolicyArn)
	return &iam.AttachUserPolicyOutput{}, nil
}

// CreateAccessKey implements IamIface.
func (c *IamClient) CreateAccessKey(input *iam.CreateAccessKeyInput) (*iam.CreateAccessKeyOutput, error) {
	cd := time.Now()
	ak := &iam.AccessKey{
		AccessKeyId:     aws.String("ACCESS_KEY"),
		CreateDate:      &cd,
		SecretAccessKey: aws.String("SECRET_KEY"),
		Status:          aws.String("Valid"),
		UserName:        input.UserName,
	}
	c.accessKeys = append(c.accessKeys, ak)
	return &iam.CreateAccessKeyOutput{
		AccessKey: ak,
	}, nil
}

// CreatePolicy implements IamIface.
func (c *IamClient) CreatePolicy(input *iam.CreatePolicyInput) (*iam.CreatePolicyOutput, error) {
	cd := time.Now()
	arn := fmt.Sprintf("arn:aws:iam::%s:policy/%s%s", c.accountid, *input.Path, *input.PolicyName)
	pol := &iam.Policy{
		Arn:                           &arn,
		CreateDate:                    &cd,
		DefaultVersionId:              aws.String("v1"),
		Description:                   input.Description,
		IsAttachable:                  aws.Bool(true),
		Path:                          input.Path,
		PermissionsBoundaryUsageCount: aws.Int64(0),
		PolicyId:                      input.PolicyName,
		PolicyName:                    input.PolicyName,
		Tags:                          input.Tags,
		UpdateDate:                    &cd,
	}

	c.policies = append(c.policies, pol)
	defaultVersion := &iam.PolicyVersion{
		CreateDate:       &cd,
		Document:         input.PolicyDocument,
		IsDefaultVersion: aws.Bool(true),
		VersionId:        aws.String("v1"),
	}
	c.policyVersions[arn] = append(c.policyVersions[arn], defaultVersion)
	return &iam.CreatePolicyOutput{
		Policy: pol,
	}, nil
}

// CreateRole implements IamIface.
func (c *IamClient) CreateRole(input *iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
	cd := time.Now()
	arn := fmt.Sprintf("arn:aws:iam::%s:role/%s%s", c.accountid, *input.Path, *input.RoleName)
	if c.getRoleByName(*input.RoleName) != nil {
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

	c.roles = append(c.roles, pol)
	return &iam.CreateRoleOutput{
		Role: &iam.Role{},
	}, nil
}

// CreateUser implements IamIface.
func (c *IamClient) CreateUser(input *iam.CreateUserInput) (*iam.CreateUserOutput, error) {
	cd := time.Now()
	arn := fmt.Sprintf("arn:aws:iam::%s:user/%s%s", c.accountid, *input.Path, *input.UserName)
	if c.getUserByName(*input.UserName) != nil {
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

	return &iam.CreateUserOutput{
		User: user,
	}, nil
}

// DeleteAccessKey implements IamIface.
func (c *IamClient) DeleteAccessKey(input *iam.DeleteAccessKeyInput) (*iam.DeleteAccessKeyOutput, error) {
	var accessKey *iam.AccessKey
	removeIndex := -1

	for i, ak := range c.accessKeys {
		if *ak.UserName == *input.UserName && *ak.AccessKeyId == *input.AccessKeyId {
			accessKey = ak
			removeIndex = i
		}
	}
	if accessKey == nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	c.accessKeys[removeIndex] = c.accessKeys[len(c.accessKeys)-1]
	c.accessKeys = c.accessKeys[:len(c.accessKeys)-1]

	return &iam.DeleteAccessKeyOutput{}, nil
}

// DeletePolicy implements IamIface.
func (c *IamClient) DeletePolicy(input *iam.DeletePolicyInput) (*iam.DeletePolicyOutput, error) {
	var policy *iam.Policy
	removeIndex := -1

	for i, pol := range c.policies {
		if *pol.Arn == *input.PolicyArn {
			policy = pol
			removeIndex = i
		}
	}
	if policy == nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	c.policies[removeIndex] = c.policies[len(c.policies)-1]
	c.policies = c.policies[:len(c.policies)-1]

	return &iam.DeletePolicyOutput{}, nil
}

// DeletePolicyVersion implements IamIface.
func (c *IamClient) DeletePolicyVersion(input *iam.DeletePolicyVersionInput) (*iam.DeletePolicyVersionOutput, error) {
	polVers, ok := c.policyVersions[*input.PolicyArn]
	if !ok {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	var policyVersion *iam.PolicyVersion
	removeIndex := -1

	for i, pol := range polVers {
		if *pol.VersionId == *input.VersionId {
			policyVersion = pol
			removeIndex = i
		}
	}
	if policyVersion == nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	polVers[removeIndex] = polVers[len(polVers)-1]
	c.policyVersions[*input.PolicyArn] = polVers[:len(polVers)-1]

	return &iam.DeletePolicyVersionOutput{}, nil
}

// DeleteRole implements IamIface.
func (c *IamClient) DeleteRole(input *iam.DeleteRoleInput) (*iam.DeleteRoleOutput, error) {
	var role *iam.Role
	removeIndex := -1

	for i, r := range c.roles {
		if *r.RoleName == *input.RoleName {
			role = r
			removeIndex = i
		}
	}
	if role == nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	c.roles[removeIndex] = c.roles[len(c.roles)-1]
	c.roles = c.roles[:len(c.roles)-1]

	return &iam.DeleteRoleOutput{}, nil
}

// DeleteUser implements IamIface.
func (c *IamClient) DeleteUser(input *iam.DeleteUserInput) (*iam.DeleteUserOutput, error) {
	var user *iam.User
	removeIndex := -1

	for i, u := range c.users {
		if *u.UserName == *input.UserName {
			user = u
			removeIndex = i
		}
	}
	if user == nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	c.users[removeIndex] = c.users[len(c.users)-1]
	c.users = c.users[:len(c.users)-1]

	return &iam.DeleteUserOutput{}, nil
}

// DeleteUserPolicy implements IamIface.
func (c *IamClient) DeleteUserPolicy(input *iam.DeleteUserPolicyInput) (*iam.DeleteUserPolicyOutput, error) {
	if _, ok := c.userInlinePolicies[*input.UserName]; !ok {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	delete(c.userInlinePolicies[*input.UserName], *input.PolicyName)
	return &iam.DeleteUserPolicyOutput{}, nil
}

// DetachRolePolicy implements IamIface.
func (c *IamClient) DetachRolePolicy(input *iam.DetachRolePolicyInput) (*iam.DetachRolePolicyOutput, error) {
	managedPols, ok := c.rolePolicyArns[*input.RoleName]
	if !ok {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	removeIndex := -1
	for i, v := range managedPols {
		if v == *input.PolicyArn {
			removeIndex = i
		}
	}
	if removeIndex == -1 {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}
	managedPols[removeIndex] = managedPols[len(managedPols)-1]
	c.rolePolicyArns[*input.RoleName] = managedPols[:len(managedPols)-1]
	return &iam.DetachRolePolicyOutput{}, nil
}

// DetachUserPolicy implements IamIface.
func (c *IamClient) DetachUserPolicy(input *iam.DetachUserPolicyInput) (*iam.DetachUserPolicyOutput, error) {
  policies, ok := c.userPolicyArns[*input.UserName]
  if !ok {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
  }
  if remIdx := FindIndex(policies, *input.PolicyArn); remIdx != -1 {
    c.userPolicyArns[*input.UserName] = DeleteIndex(policies, remIdx)
    return &iam.DetachUserPolicyOutput{}, nil
  } else {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
  }
}

// GetPolicy implements IamIface.
func (c *IamClient) GetPolicy(input *iam.GetPolicyInput) (*iam.GetPolicyOutput, error) {
  polIdx := FindIndexFunc(c.policies, func(elem *iam.Policy) bool {
    return *elem.Arn == *input.PolicyArn
  })

  if polIdx == -1 {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
  }
  return &iam.GetPolicyOutput{
  	Policy: c.policies[polIdx],
  }, nil
}

// GetPolicyVersion implements IamIface.
func (c *IamClient) GetPolicyVersion(input *iam.GetPolicyVersionInput) (*iam.GetPolicyVersionOutput, error) {
  versions, ok := c.policyVersions[*input.PolicyArn]
  if !ok {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
  }
  versionIdx := FindIndexFunc(versions, func(elem *iam.PolicyVersion) bool {
    return *elem.VersionId == *input.VersionId
  })
  if versionIdx == -1 {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
  }

  return &iam.GetPolicyVersionOutput{
  	PolicyVersion: versions[versionIdx],
  }, nil
}

// GetRole implements IamIface.
func (c *IamClient) GetRole(input *iam.GetRoleInput) (*iam.GetRoleOutput, error) {
  roleIdx := FindIndexFunc(c.roles, func(elem *iam.Role) bool {
    return *elem.RoleName == *input.RoleName
  })
  if roleIdx == -1 {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
  }
  return &iam.GetRoleOutput{
  	Role: c.roles[roleIdx],
  },nil
}

// GetUser implements IamIface.
func (c *IamClient) GetUser(input *iam.GetUserInput) (*iam.GetUserOutput, error) {
  userIdx := FindIndexFunc(c.users, func(elem *iam.User) bool {
    return *elem.UserName == *input.UserName
  })
  if userIdx == -1 {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
  }
  return &iam.GetUserOutput{
  	User: c.users[userIdx],
  },nil
}

// ListAccessKeys implements IamIface.
func (c *IamClient) ListAccessKeys(input *iam.ListAccessKeysInput) (*iam.ListAccessKeysOutput, error) {
  accessKeys := FilterFunc(c.accessKeys, func(elem *iam.AccessKey) bool {
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


// ListAttachedRolePolicies implements IamIface.
func (c *IamClient) ListAttachedRolePolicies(input *iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
  roleIndex := FindIndexFunc(c.roles, func(elem *iam.Role) bool {
    return *elem.RoleName == *input.RoleName
  })

  roleArn := c.roles[roleIndex].Arn
  return &iam.ListAttachedRolePoliciesOutput{
  	AttachedPolicies: []*iam.AttachedPolicy{{
  		PolicyArn:  roleArn,
  		PolicyName: new(string),
  	}},
  	IsTruncated:      new(bool),
  	Marker:           new(string),
  }, nil
}

// ListAttachedUserPolicies implements IamIface.
func (*IamClient) ListAttachedUserPolicies(*iam.ListAttachedUserPoliciesInput) (*iam.ListAttachedUserPoliciesOutput, error) {
	panic("unimplemented")
}

// ListPolicies implements IamIface.
func (*IamClient) ListPolicies(*iam.ListPoliciesInput) (*iam.ListPoliciesOutput, error) {
	panic("unimplemented")
}

// ListPolicyVersions implements IamIface.
func (*IamClient) ListPolicyVersions(input *iam.ListPolicyVersionsInput) (*iam.ListPolicyVersionsOutput, error) {
	panic("unimplemented")
}

// ListRoles implements IamIface.
func (*IamClient) ListRoles(input *iam.ListRolesInput) (*iam.ListRolesOutput, error) {
	panic("unimplemented")
}

// ListUserPolicies implements IamIface.
func (*IamClient) ListUserPolicies(*iam.ListUserPoliciesInput) (*iam.ListUserPoliciesOutput, error) {
	panic("unimplemented")
}

// ListUserTags implements IamIface.
func (*IamClient) ListUserTags(*iam.ListUserTagsInput) (*iam.ListUserTagsOutput, error) {
	panic("unimplemented")
}

// ListUsers implements IamIface.
func (*IamClient) ListUsers(*iam.ListUsersInput) (*iam.ListUsersOutput, error) {
	panic("unimplemented")
}

// ListUsersPages implements IamIface.
func (*IamClient) ListUsersPages(*iam.ListUsersInput, func(*iam.ListUsersOutput, bool) bool) error {
	panic("unimplemented")
}

// PutUserPolicy implements IamIface.
func (c *IamClient) PutUserPolicy(input *iam.PutUserPolicyInput) (*iam.PutUserPolicyOutput, error) {
	if _, ok := c.userInlinePolicies[*input.UserName]; !ok {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}
	c.userInlinePolicies[*input.UserName][*input.PolicyName] = input.PolicyDocument
	return &iam.PutUserPolicyOutput{}, nil
}
