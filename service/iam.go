package service

import (
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
)

type IamCrud struct {
  iamiface.IAMAPI
  Accountid string
}

func (c *IamCrud) AttachRolePolicy(input *iam.AttachRolePolicyInput) (*iam.AttachRolePolicyOutput, error) {
	role := ClientStore.getRoleByName(*input.RoleName)
	if role == nil {
		return &iam.AttachRolePolicyOutput{}, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}
	ClientStore.RoleAttachedPolicies[*role.Arn] = append(ClientStore.RoleAttachedPolicies[*role.Arn], *input.PolicyArn)
	return &iam.AttachRolePolicyOutput{}, nil
}

func (c *IamCrud) AttachUserPolicy(input *iam.AttachUserPolicyInput) (*iam.AttachUserPolicyOutput, error) {
	user := ClientStore.getUserByName(*input.UserName)
	if user == nil {
		return &iam.AttachUserPolicyOutput{}, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}
	ClientStore.UserAttachedPolicies[*user.Arn] = append(ClientStore.UserAttachedPolicies[*user.Arn], *input.PolicyArn)
	return &iam.AttachUserPolicyOutput{}, nil
}

func (c *IamCrud) CreateAccessKey(input *iam.CreateAccessKeyInput) (*iam.CreateAccessKeyOutput, error) {
	cd := time.Now()
	ak := &iam.AccessKey{
		AccessKeyId:     aws.String("ACCESS_KEY"),
		CreateDate:      &cd,
		SecretAccessKey: aws.String("SECRET_KEY"),
		Status:          aws.String("Valid"),
		UserName:        input.UserName,
	}
	ClientStore.AccessKeys = append(ClientStore.AccessKeys, ak)
	return &iam.CreateAccessKeyOutput{
		AccessKey: ak,
	}, nil
}


func (c *IamCrud) CreatePolicy(input *iam.CreatePolicyInput) (*iam.CreatePolicyOutput, error) {
	cd := time.Now()
	arn := fmt.Sprintf("arn:aws:iam::%s:policy/%s%s", c.Accountid, *input.Path, *input.PolicyName)
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

	ClientStore.Policies = append(ClientStore.Policies, pol)
	defaultVersion := &iam.PolicyVersion{
		CreateDate:       &cd,
		Document:         input.PolicyDocument,
		IsDefaultVersion: aws.Bool(true),
		VersionId:        aws.String("v1"),
	}
	ClientStore.PolicyVersions[arn] = append(ClientStore.PolicyVersions[arn], defaultVersion)
	return &iam.CreatePolicyOutput{
		Policy: pol,
	}, nil
}

func (c *IamCrud) CreateRole(input *iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
	cd := time.Now()
	arn := fmt.Sprintf("arn:aws:iam::%s:role/%s%s", c.Accountid, *input.Path, *input.RoleName)
	if ClientStore.getRoleByName(*input.RoleName) != nil {
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

	ClientStore.Roles = append(ClientStore.Roles, pol)
	return &iam.CreateRoleOutput{
		Role: &iam.Role{},
	}, nil
}

func (c *IamCrud) CreateUser(input *iam.CreateUserInput) (*iam.CreateUserOutput, error) {
	cd := time.Now()
	arn := fmt.Sprintf("arn:aws:iam::%s:user/%s%s", c.Accountid, *input.Path, *input.UserName)
	if ClientStore.getUserByName(*input.UserName) != nil {
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

  ClientStore.Users = append(ClientStore.Users, user)

	return &iam.CreateUserOutput{
		User: user,
	}, nil
}

func (c *IamCrud) DeleteAccessKey(input *iam.DeleteAccessKeyInput) (*iam.DeleteAccessKeyOutput, error) {
	var accessKey *iam.AccessKey
	removeIndex := -1

	for i, ak := range ClientStore.AccessKeys {
		if *ak.UserName == *input.UserName && *ak.AccessKeyId == *input.AccessKeyId {
			accessKey = ak
			removeIndex = i
		}
	}
	if accessKey == nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	ClientStore.AccessKeys[removeIndex] = ClientStore.AccessKeys[len(ClientStore.AccessKeys)-1]
	ClientStore.AccessKeys = ClientStore.AccessKeys[:len(ClientStore.AccessKeys)-1]

	return &iam.DeleteAccessKeyOutput{}, nil
}

func (c *IamCrud) DeletePolicy(input *iam.DeletePolicyInput) (*iam.DeletePolicyOutput, error) {
	var policy *iam.Policy
	removeIndex := -1

	for i, pol := range ClientStore.Policies {
		if *pol.Arn == *input.PolicyArn {
			policy = pol
			removeIndex = i
		}
	}
	if policy == nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	ClientStore.Policies[removeIndex] = ClientStore.Policies[len(ClientStore.Policies)-1]
	ClientStore.Policies = ClientStore.Policies[:len(ClientStore.Policies)-1]

	return &iam.DeletePolicyOutput{}, nil
}

func (c *IamCrud) DeletePolicyVersion(input *iam.DeletePolicyVersionInput) (*iam.DeletePolicyVersionOutput, error) {
	polVers, ok := ClientStore.PolicyVersions[*input.PolicyArn]
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
	ClientStore.PolicyVersions[*input.PolicyArn] = polVers[:len(polVers)-1]

	return &iam.DeletePolicyVersionOutput{}, nil
}

func (c *IamCrud) DeleteRole(input *iam.DeleteRoleInput) (*iam.DeleteRoleOutput, error) {
	var role *iam.Role
	removeIndex := -1

	for i, r := range ClientStore.Roles {
		if *r.RoleName == *input.RoleName {
			role = r
			removeIndex = i
		}
	}
	if role == nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	ClientStore.Roles[removeIndex] = ClientStore.Roles[len(ClientStore.Roles)-1]
	ClientStore.Roles = ClientStore.Roles[:len(ClientStore.Roles)-1]

	return &iam.DeleteRoleOutput{}, nil
}

func (c *IamCrud) DeleteUser(input *iam.DeleteUserInput) (*iam.DeleteUserOutput, error) {
	var user *iam.User
	removeIndex := -1

	for i, u := range ClientStore.Users {
		if *u.UserName == *input.UserName {
			user = u
			removeIndex = i
		}
	}
	if user == nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	ClientStore.Users[removeIndex] = ClientStore.Users[len(ClientStore.Users)-1]
	ClientStore.Users = ClientStore.Users[:len(ClientStore.Users)-1]

	return &iam.DeleteUserOutput{}, nil
}

func (c *IamCrud) DeleteUserPolicy(input *iam.DeleteUserPolicyInput) (*iam.DeleteUserPolicyOutput, error) {
	if _, ok := ClientStore.UserInlinePolicies[*input.UserName]; !ok {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	delete(ClientStore.UserInlinePolicies[*input.UserName], *input.PolicyName)
	return &iam.DeleteUserPolicyOutput{}, nil
}

func (c *IamCrud) DetachRolePolicy(input *iam.DetachRolePolicyInput) (*iam.DetachRolePolicyOutput, error) {
	managedPols, ok := ClientStore.RoleAttachedPolicies[*input.RoleName]
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
	ClientStore.RoleAttachedPolicies[*input.RoleName] = managedPols[:len(managedPols)-1]
	return &iam.DetachRolePolicyOutput{}, nil
}

func (c *IamCrud) DetachUserPolicy(input *iam.DetachUserPolicyInput) (*iam.DetachUserPolicyOutput, error) {
  policies, ok := ClientStore.UserAttachedPolicies[*input.UserName]
  if !ok {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
  }
  if remIdx := FindIndex(policies, *input.PolicyArn); remIdx != -1 {
    ClientStore.UserAttachedPolicies[*input.UserName] = DeleteIndex(policies, remIdx)
    return &iam.DetachUserPolicyOutput{}, nil
  } else {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
  }
}

func (c *IamCrud) GetPolicy(input *iam.GetPolicyInput) (*iam.GetPolicyOutput, error) {
  polIdx := FindIndexFunc(ClientStore.Policies, func(elem *iam.Policy) bool {
    return *elem.Arn == *input.PolicyArn
  })

  if polIdx == -1 {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
  }
  return &iam.GetPolicyOutput{
  	Policy: ClientStore.Policies[polIdx],
  }, nil
}

func (c *IamCrud) GetPolicyVersion(input *iam.GetPolicyVersionInput) (*iam.GetPolicyVersionOutput, error) {
  versions, ok := ClientStore.PolicyVersions[*input.PolicyArn]
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

func (c *IamCrud) GetRole(input *iam.GetRoleInput) (*iam.GetRoleOutput, error) {
  roleIdx := FindIndexFunc(ClientStore.Roles, func(elem *iam.Role) bool {
    return *elem.RoleName == *input.RoleName
  })
  if roleIdx == -1 {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
  }
  return &iam.GetRoleOutput{
  	Role: ClientStore.Roles[roleIdx],
  },nil
}

func (c *IamCrud) GetUser(input *iam.GetUserInput) (*iam.GetUserOutput, error) {
  userIdx := FindIndexFunc(ClientStore.Users, func(elem *iam.User) bool {
    return *elem.UserName == *input.UserName
  })
  if userIdx == -1 {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
  }
  return &iam.GetUserOutput{
  	User: ClientStore.Users[userIdx],
  },nil
}

func (c *IamCrud) ListAccessKeys(input *iam.ListAccessKeysInput) (*iam.ListAccessKeysOutput, error) {
  accessKeys := FilterFunc(ClientStore.AccessKeys, func(elem *iam.AccessKey) bool {
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

func (c *IamCrud) ListAttachedRolePolicies(input *iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
  roleIndex := FindIndexFunc(ClientStore.Roles, func(elem *iam.Role) bool {
    return *elem.RoleName == *input.RoleName
  })

  roleArn := ClientStore.Roles[roleIndex].Arn
  return &iam.ListAttachedRolePoliciesOutput{
  	AttachedPolicies: []*iam.AttachedPolicy{{
  		PolicyArn:  roleArn,
  		PolicyName: new(string),
  	}},
  	IsTruncated:      new(bool),
  	Marker:           new(string),
  }, nil
}

func (c *IamCrud) ListAttachedUserPolicies(input *iam.ListAttachedUserPoliciesInput) (*iam.ListAttachedUserPoliciesOutput, error) {
  panic("Not Implemented")
}

func (c *IamCrud) ListPolicies(input *iam.ListPoliciesInput) (*iam.ListPoliciesOutput, error) {
  panic("Not Implemented")
}

func (c *IamCrud) ListPolicyVersions(input *iam.ListPolicyVersionsInput) (*iam.ListPolicyVersionsOutput, error) {
  panic("Not Implemented")
}

func (c *IamCrud) ListRoles(input *iam.ListRolesInput) (*iam.ListRolesOutput, error) {
  panic("Not Implemented")
}

func (c *IamCrud) ListUserPolicies(input *iam.ListUserPoliciesInput) (*iam.ListUserPoliciesOutput, error) {
  panic("Not Implemented")
}

func (c *IamCrud) ListUserTags(input *iam.ListUserTagsInput) (*iam.ListUserTagsOutput, error) {
  panic("Not Implemented")
}

func (c *IamCrud) ListUsers(input *iam.ListUsersInput) (*iam.ListUsersOutput, error) {
  panic("Not Implemented")
}

func (c *IamCrud) ListUsersPages(input *iam.ListUsersInput, _ func(*iam.ListUsersOutput, bool) bool) error {
  panic("Not Implemented")
}

func (c *IamCrud) PutUserPolicy(input *iam.PutUserPolicyInput) (*iam.PutUserPolicyOutput, error) {
	if _, ok := ClientStore.UserInlinePolicies[*input.UserName]; !ok {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}
	ClientStore.UserInlinePolicies[*input.UserName][*input.PolicyName] = input.PolicyDocument
	return &iam.PutUserPolicyOutput{}, nil
}
