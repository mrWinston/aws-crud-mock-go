package service

import (
	"fmt"
	"reflect"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
)

type IamCrudGeneric struct {
	iamiface.IAMAPI
	Accountid string
}

type RolePolicycAttachement struct {
	Arn                  string
	AttachTargetRoleName string
	AttachedPolicyArn    string
}

type UserPolicyAttachement struct {
	Arn                  string
	AttachTargetUserName string
	AttachedPolicyArn    string
}

type UserInlinePolicy struct {
	Arn                  string
	InlinePolicyName     string
	InlinePolicyDocument string
	InlinePolicyUserName string
}

type PolicyVersionMapping struct {
	Arn             string
	TargetPolicyArn string
	PolicyVersion   *iam.PolicyVersion
}

type AccessKeyWrapper struct {
	Arn               string
	AccessKeyUserName string
	AccessKey         *iam.AccessKey
}

func (c *IamCrudGeneric) AttachRolePolicy(input *iam.AttachRolePolicyInput) (*iam.AttachRolePolicyOutput, error) {
	arn := fmt.Sprintf("role-%s-%s", *input.RoleName, *input.PolicyArn)
	role := allStore.GetThingByFieldName("RoleName", *input.RoleName).(*iam.Role)
	if role == nil {
		return &iam.AttachRolePolicyOutput{}, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}
	if allStore.GetThingByArn(arn) == nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	allStore.PutThing(RolePolicycAttachement{
		Arn:                  arn,
		AttachTargetRoleName: *input.RoleName,
		AttachedPolicyArn:    *input.PolicyArn,
	})
	return &iam.AttachRolePolicyOutput{}, nil
}

func (c *IamCrudGeneric) AttachUserPolicy(input *iam.AttachUserPolicyInput) (*iam.AttachUserPolicyOutput, error) {
	arn := fmt.Sprintf("user-%s-%s", *input.UserName, *input.PolicyArn)
	user := allStore.GetThingByFieldName("UserName", *input.UserName).(*iam.User)
	if user == nil {
		return &iam.AttachUserPolicyOutput{}, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}
	if allStore.GetThingByArn(arn) == nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}
	allStore.PutThing(UserPolicyAttachement{
		Arn:                  arn,
		AttachTargetUserName: *input.UserName,
		AttachedPolicyArn:    *input.PolicyArn,
	})
	return &iam.AttachUserPolicyOutput{}, nil
}

func (c *IamCrudGeneric) CreateAccessKey(input *iam.CreateAccessKeyInput) (*iam.CreateAccessKeyOutput, error) {
	cd := time.Now()
	ak := &iam.AccessKey{
		AccessKeyId:     aws.String("ACCESS_KEY"),
		CreateDate:      &cd,
		SecretAccessKey: aws.String("SECRET_KEY"),
		Status:          aws.String("Valid"),
		UserName:        input.UserName,
	}

	allStore.PutThing(AccessKeyWrapper{
		Arn: fmt.Sprintf("ak-%s-%s", *input.UserName, *ak.AccessKeyId),
    AccessKeyUserName: *input.UserName,
    AccessKey: ak,
	})
	return &iam.CreateAccessKeyOutput{
		AccessKey: ak,
	}, nil
}

func (c *IamCrudGeneric) CreatePolicy(input *iam.CreatePolicyInput) (*iam.CreatePolicyOutput, error) {
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
	allStore.PutThing(pol)
	defaultVersion := &iam.PolicyVersion{
		CreateDate:       &cd,
		Document:         input.PolicyDocument,
		IsDefaultVersion: aws.Bool(true),
		VersionId:        aws.String("v1"),
	}
	allStore.PutThing(PolicyVersionMapping{
		Arn:             fmt.Sprintf("policyversion-%s-%s", *pol.Arn, *defaultVersion.VersionId),
		TargetPolicyArn: *pol.Arn,
		PolicyVersion:   defaultVersion,
	})

	return &iam.CreatePolicyOutput{
		Policy: pol,
	}, nil
}

func (c *IamCrudGeneric) CreateRole(input *iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
	cd := time.Now()
	arn := fmt.Sprintf("arn:aws:iam::%s:role/%s%s", c.Accountid, *input.Path, *input.RoleName)

	if allStore.GetThingByFieldName("RoleName", *input.RoleName) != nil {
		return nil, awserr.New(iam.ErrCodeInvalidInputException, "", nil)
	}

	newrole := &iam.Role{
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

	allStore.PutThing(newrole)
	return &iam.CreateRoleOutput{
		Role: newrole,
	}, nil
}

func (c *IamCrudGeneric) CreateUser(input *iam.CreateUserInput) (*iam.CreateUserOutput, error) {
	cd := time.Now()
	arn := fmt.Sprintf("arn:aws:iam::%s:user/%s%s", c.Accountid, *input.Path, *input.UserName)
	if allStore.GetThingByFieldName("UserName", *input.UserName) != nil {
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

	allStore.PutThing(user)

	return &iam.CreateUserOutput{
		User: user,
	}, nil
}

func (c *IamCrudGeneric) DeleteAccessKey(input *iam.DeleteAccessKeyInput) (*iam.DeleteAccessKeyOutput, error) {
	accessKey := allStore.RemoveThingByFieldName("AccessKeyId", *input.AccessKeyId).(*iam.AccessKey)
	if accessKey == nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}
	return &iam.DeleteAccessKeyOutput{}, nil
}

func (c *IamCrudGeneric) DeletePolicy(input *iam.DeletePolicyInput) (*iam.DeletePolicyOutput, error) {
	policy := allStore.RemoveThingByFieldName("Arn", *input.PolicyArn)
	if policy == nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	return &iam.DeletePolicyOutput{}, nil
}

func (c *IamCrudGeneric) DeletePolicyVersion(input *iam.DeletePolicyVersionInput) (*iam.DeletePolicyVersionOutput, error) {
	idxs := allStore.ListAllIdxByFieldName("TargetPolicyArn", *input.PolicyArn)

	for _, v := range idxs {
		vm := allStore.all[v].(PolicyVersionMapping)
		if *vm.PolicyVersion.VersionId == *input.VersionId {
			allStore.RemoveThingByIdx(v)
			return &iam.DeletePolicyVersionOutput{}, nil
		}
	}
	return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
}

func (c *IamCrudGeneric) DeleteRole(input *iam.DeleteRoleInput) (*iam.DeleteRoleOutput, error) {
	if allStore.RemoveThingByFieldName("RoleName", *input.RoleName) == nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}
	return &iam.DeleteRoleOutput{}, nil
}

func (c *IamCrudGeneric) DeleteUser(input *iam.DeleteUserInput) (*iam.DeleteUserOutput, error) {
	if allStore.RemoveThingByFieldName("UserName", *input.UserName) == nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	return &iam.DeleteUserOutput{}, nil
}

func (c *IamCrudGeneric) DeleteUserPolicy(input *iam.DeleteUserPolicyInput) (*iam.DeleteUserPolicyOutput, error) {
	if allStore.RemoveThingByFieldName("Arn", fmt.Sprintf("user-%s-%s", *input.UserName, *input.PolicyName)) == nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	return &iam.DeleteUserPolicyOutput{}, nil
}

func (c *IamCrudGeneric) DetachRolePolicy(input *iam.DetachRolePolicyInput) (*iam.DetachRolePolicyOutput, error) {
	arn := fmt.Sprintf("role-%s-%s", *input.RoleName, *input.PolicyArn)

	if allStore.RemoveThingByArn(arn) == nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	return &iam.DetachRolePolicyOutput{}, nil
}

func (c *IamCrudGeneric) DetachUserPolicy(input *iam.DetachUserPolicyInput) (*iam.DetachUserPolicyOutput, error) {
	arn := fmt.Sprintf("user-%s-%s", *input.UserName, *input.PolicyArn)

	if allStore.RemoveThingByArn(arn) == nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	return &iam.DetachUserPolicyOutput{}, nil
}

func (c *IamCrudGeneric) GetPolicy(input *iam.GetPolicyInput) (*iam.GetPolicyOutput, error) {
	policy := allStore.GetThingByArn(*input.PolicyArn).(*iam.Policy)
	return &iam.GetPolicyOutput{
		Policy: policy,
	}, nil
}

func (c *IamCrudGeneric) GetPolicyVersion(input *iam.GetPolicyVersionInput) (*iam.GetPolicyVersionOutput, error) {
	pv := allStore.GetThingByArn(fmt.Sprintf("policyversion-%s-%s", *input.PolicyArn, *input.VersionId)).(PolicyVersionMapping)
	if pv.TargetPolicyArn == "" {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	return &iam.GetPolicyVersionOutput{
		PolicyVersion: pv.PolicyVersion,
	}, nil
}

func (c *IamCrudGeneric) GetRole(input *iam.GetRoleInput) (*iam.GetRoleOutput, error) {
	role := allStore.GetThingByFieldName("RoleName", *input.RoleName).(*iam.Role)
	if role == nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}
	return &iam.GetRoleOutput{
		Role: role,
	}, nil
}

func (c *IamCrudGeneric) GetUser(input *iam.GetUserInput) (*iam.GetUserOutput, error) {
	user := allStore.GetThingByFieldName("UserName", *input.UserName).(*iam.User)
	if user == nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}
	return &iam.GetUserOutput{
		User: user,
	}, nil
}

func (c *IamCrudGeneric) ListAccessKeys(input *iam.ListAccessKeysInput) (*iam.ListAccessKeysOutput, error) {

  accessKeys := allStore.GetAllThingsByFieldName("AccessKeyUserName", *input.UserName)

	metadatas := []*iam.AccessKeyMetadata{}

	for _, el := range accessKeys {
    akw, ok := el.(AccessKeyWrapper)
    if !ok {
      continue
    }
    ak := akw.AccessKey
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

func (c *IamCrudGeneric) ListAttachedRolePolicies(input *iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
  
  els := allStore.GetAllThingsByFieldName("AttachTargetRoleName", *input.RoleName)
  
  attachedPolicies := []*iam.AttachedPolicy{}
  for _, v := range els {
    pw := v.(RolePolicycAttachement)
    attachedPolicies = append(attachedPolicies, &iam.AttachedPolicy{
    	PolicyArn:  &pw.AttachedPolicyArn,
    	PolicyName: new(string),
    })
  }

	return &iam.ListAttachedRolePoliciesOutput{
		AttachedPolicies: attachedPolicies,
		IsTruncated: new(bool),
		Marker:      new(string),
	}, nil
}

func (c *IamCrudGeneric) ListAttachedUserPolicies(input *iam.ListAttachedUserPoliciesInput) (*iam.ListAttachedUserPoliciesOutput, error) {
  els := allStore.GetAllThingsByFieldName("AttachTargetUserName", *input.UserName)
  
  attachedPolicies := []*iam.AttachedPolicy{}
  for _, v := range els {
    pw := v.(UserPolicyAttachement)
    attachedPolicies = append(attachedPolicies, &iam.AttachedPolicy{
    	PolicyArn:  &pw.AttachedPolicyArn,
    	PolicyName: new(string),
    })
  }

	return &iam.ListAttachedUserPoliciesOutput{
		AttachedPolicies: attachedPolicies,
		IsTruncated: new(bool),
		Marker:      new(string),
	}, nil
}

// TODO: Support some filter
func (c *IamCrudGeneric) ListPolicies(input *iam.ListPoliciesInput) (*iam.ListPoliciesOutput, error) {
  raw := allStore.GetAllThingsByType(reflect.TypeOf(&iam.Policy{}))
  policies := make([]*iam.Policy, len(raw))

  for i, v := range raw {
    policies[i] = v.(*iam.Policy)
  }

  return &iam.ListPoliciesOutput{
  	IsTruncated: aws.Bool(false),
  	Policies:    policies,
  }, nil

}

func (c *IamCrudGeneric) ListPolicyVersions(input *iam.ListPolicyVersionsInput) (*iam.ListPolicyVersionsOutput, error) {
  raw := allStore.GetAllThingsByFieldName("TargetPolicyArn", *input.PolicyArn)
  versions := make([]*iam.PolicyVersion, len(raw))

  for i, v := range raw {
    pw := v.(PolicyVersionMapping)
    versions[i] = pw.PolicyVersion
  }

  return &iam.ListPolicyVersionsOutput{
  	IsTruncated: aws.Bool(false),
  	Versions:    versions,
  }, nil
}

// TODO: Support some filter
func (c *IamCrudGeneric) ListRoles(input *iam.ListRolesInput) (*iam.ListRolesOutput, error) {
  raw := allStore.GetAllThingsByType(reflect.TypeOf(&iam.Role{}))
  roles := make([]*iam.Role, len(raw))

  for i, v := range raw {
    roles[i] = v.(*iam.Role)
  }

  return &iam.ListRolesOutput{
  	IsTruncated: aws.Bool(false),
  	Roles:    roles,
  }, nil
  
}

func (c *IamCrudGeneric) ListUserPolicies(input *iam.ListUserPoliciesInput) (*iam.ListUserPoliciesOutput, error) {
  raw := allStore.GetAllThingsByFieldName("InlinePolicyUserName", *input.UserName)
  policyNames := make([]*string, len(raw))

  for i, v := range raw {
    pw := v.(UserInlinePolicy)
    policyNames[i] = &pw.InlinePolicyName
  }  
  return &iam.ListUserPoliciesOutput{
  	PolicyNames: policyNames,
  }, nil
}

func (c *IamCrudGeneric) ListUserTags(input *iam.ListUserTagsInput) (*iam.ListUserTagsOutput, error) {
	panic("Not Implemented")
}

func (c *IamCrudGeneric) ListUsers(input *iam.ListUsersInput) (*iam.ListUsersOutput, error) {
	panic("Not Implemented")
}

func (c *IamCrudGeneric) ListUsersPages(input *iam.ListUsersInput, fn func(*iam.ListUsersOutput, bool) bool) error {
  raw := allStore.GetAllThingsByType(reflect.TypeOf(&iam.User{}))
  users := make([]*iam.User, len(raw))
  for i, v := range raw {
    users[i] = v.(*iam.User)
  }

  fn(&iam.ListUsersOutput{
  	IsTruncated: aws.Bool(false),
  	Users:       users,
  }, false)
  return nil
}

func (c *IamCrudGeneric) PutUserPolicy(input *iam.PutUserPolicyInput) (*iam.PutUserPolicyOutput, error) {
	arn := fmt.Sprintf("%s-%s", *input.UserName, *input.PolicyName)
	if allStore.GetThingByArn(arn) == nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}
	allStore.PutThing(UserInlinePolicy{
		Arn:                  fmt.Sprintf("user-%s-%s", *input.UserName, *input.PolicyName),
		InlinePolicyName:     *input.PolicyName,
		InlinePolicyDocument: *input.PolicyDocument,
		InlinePolicyUserName: *input.UserName,
	})
	return &iam.PutUserPolicyOutput{}, nil
}
