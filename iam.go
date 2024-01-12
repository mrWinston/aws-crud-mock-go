package goawscrudclient

import (
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/timshannon/badgerhold/v4"
)

type IamCrud struct {
	iamiface.IAMAPI
	AccountId   string
	AccessKeyId string
}

type RolePolicyAttachement struct {
	RoleArn   string
	PolicyArn string
}

type UserPolicyAttachement struct {
	UserArn   string
	PolicyArn string
}

type UserInlinePolicy struct {
	PolicyName     string
	PolicyDocument string
	UserArn        string
}

type PolicyVersionWrapper struct {
	PolicyArn     string
	PolicyVersion *iam.PolicyVersion
}

type AccessKeyWrapper struct {
	UserArn   string
	AccessKey *iam.AccessKey
}

func (c *IamCrud) AttachRolePolicy(input *iam.AttachRolePolicyInput) (*iam.AttachRolePolicyOutput, error) {
	roleArn := GenerateIamArn(&c.AccountId, aws.String("role"), nil, input.RoleName)
	role := &iam.Role{}
	err := BH().Get(roleArn, role)
	if err != nil {
		return &iam.AttachRolePolicyOutput{}, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	err = BH().Insert(badgerhold.NextSequence(), RolePolicyAttachement{
		RoleArn:   *role.Arn,
		PolicyArn: *input.PolicyArn,
	})

	if err != nil {
		return &iam.AttachRolePolicyOutput{}, awserr.New(iam.ErrCodeInvalidInputException, "", nil)
	}

	return &iam.AttachRolePolicyOutput{}, nil
}

func (c *IamCrud) AttachUserPolicy(input *iam.AttachUserPolicyInput) (*iam.AttachUserPolicyOutput, error) {
	user := &iam.User{}
	userArn := GenerateIamArn(&c.AccountId, aws.String("user"), nil, input.UserName)
	err := BH().Get(userArn, user)
	if err != nil {
		return &iam.AttachUserPolicyOutput{}, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)

	}

	err = BH().Insert(badgerhold.NextSequence(), UserPolicyAttachement{
		UserArn:   userArn,
		PolicyArn: *input.PolicyArn,
	})

	if err != nil {
		return nil, awserr.New(iam.ErrCodeInvalidInputException, "", nil)
	}
	return &iam.AttachUserPolicyOutput{}, nil
}

func (c *IamCrud) CreateAccessKey(input *iam.CreateAccessKeyInput) (*iam.CreateAccessKeyOutput, error) {
	cd := time.Now().UTC()
	ak := &iam.AccessKey{
		AccessKeyId:     aws.String("ACCESS_KEY"),
		CreateDate:      &cd,
		SecretAccessKey: aws.String("SECRET_KEY"),
		Status:          aws.String("Valid"),
		UserName:        input.UserName,
	}

	userArn := GenerateIamArn(&c.AccountId, aws.String("user"), nil, input.UserName)
	err := BH().Insert(badgerhold.NextSequence(), AccessKeyWrapper{
		UserArn:   userArn,
		AccessKey: ak,
	})
	if err != nil {
		return nil, awserr.New(iam.ErrCodeInvalidInputException, "", nil)
	}

	return &iam.CreateAccessKeyOutput{
		AccessKey: ak,
	}, nil
}

// TODO: Check if already exists
func (c *IamCrud) CreatePolicy(input *iam.CreatePolicyInput) (*iam.CreatePolicyOutput, error) {
	cd := time.Now().UTC()
	arn := fmt.Sprintf("arn:aws:iam::%s:policy/%s%s", c.AccountId, *input.Path, *input.PolicyName)
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

	err := BH().Insert(pol.Arn, pol)

	if err != nil {
		return nil, awserr.New(iam.ErrCodeInvalidInputException, "", nil)
	}
	defaultVersion := &iam.PolicyVersion{
		CreateDate:       &cd,
		Document:         input.PolicyDocument,
		IsDefaultVersion: aws.Bool(true),
		VersionId:        aws.String("v1"),
	}
	err = BH().Insert(badgerhold.NextSequence(), PolicyVersionWrapper{
		PolicyArn:     *pol.Arn,
		PolicyVersion: defaultVersion,
	})
	if err != nil {
		return nil, awserr.New(iam.ErrCodeInvalidInputException, "", nil)
	}

	return &iam.CreatePolicyOutput{
		Policy: pol,
	}, nil
}

func (c *IamCrud) CreateRole(input *iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
	cd := time.Now()

	arn := GenerateIamArn(&c.AccountId, aws.String("role"), input.Path, input.RoleName)
	role := &iam.Role{}
	err := BH().Get(arn, role)

	if err == nil {
		return nil, awserr.New(iam.ErrCodeInvalidInputException, "", err)
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

	err = BH().Insert(newrole.Arn, newrole)

	if err != nil {
		return nil, awserr.New(iam.ErrCodeInvalidInputException, "", err)
	}

	return &iam.CreateRoleOutput{
		Role: newrole,
	}, nil
}

func GenerateIamArn(accountID *string, resource *string, path *string, name *string) string {
	accValue := ""
	if accountID != nil {
		accValue = *accountID
	}

	resourceValue := ""
	if resource != nil {
		resourceValue = *resource
	}

	pathValue := ""
	if path != nil {
		pathValue = *path
	}

	nameValue := ""
	if name != nil {
		nameValue = *name
	}

	return fmt.Sprintf("arn:aws:iam::%s:%s/%s%s", accValue, resourceValue, pathValue, nameValue)
}

func (c *IamCrud) CreateUser(input *iam.CreateUserInput) (*iam.CreateUserOutput, error) {
	cd := time.Now()
	arn := GenerateIamArn(&c.AccountId, aws.String("user"), input.Path, input.UserName)
	user := &iam.User{}
	err := BH().Get(arn, user)
	if err == nil {
		return nil, awserr.New(iam.ErrCodeInvalidInputException, "", err)
	}

	newUser := &iam.User{
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

	err = BH().Insert(newUser.Arn, newUser)

	if err != nil {
		return nil, awserr.New(iam.ErrCodeInvalidInputException, "", nil)
	}
	return &iam.CreateUserOutput{
		User: newUser,
	}, nil
}

// TODO: Determine UserName based on the person who calls it
func (c *IamCrud) DeleteAccessKey(input *iam.DeleteAccessKeyInput) (*iam.DeleteAccessKeyOutput, error) {
	ak := &iam.AccessKey{}
	err := BH().DeleteMatching(ak, badgerhold.Where("UserName").Eq(input.UserName).And("AccessKeyId").Eq(input.AccessKeyId))
	if err != nil {
		return nil, awserr.New(iam.ErrCodeInvalidInputException, "", nil)
	}
	return &iam.DeleteAccessKeyOutput{}, nil
}

func (c *IamCrud) DeletePolicy(input *iam.DeletePolicyInput) (*iam.DeletePolicyOutput, error) {
	policy := &iam.Policy{}
	err := BH().Delete(input.PolicyArn, policy)
	if err != nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	return &iam.DeletePolicyOutput{}, nil
}

func (c *IamCrud) DeletePolicyVersion(input *iam.DeletePolicyVersionInput) (*iam.DeletePolicyVersionOutput, error) {
	pvw := &PolicyVersionWrapper{}
	err := BH().DeleteMatching(pvw, badgerhold.Where("PolicyArn").Eq(input.PolicyArn).And("PolicyVersion.VersionId").Eq(input.VersionId))
	if err != nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
}

func (c *IamCrud) DeleteRole(input *iam.DeleteRoleInput) (*iam.DeleteRoleOutput, error) {
	role := &iam.Role{}
	err := BH().DeleteMatching(role, badgerhold.Where("RoleName").Eq(input.RoleName))

	if err != nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}
	return &iam.DeleteRoleOutput{}, nil
}

func (c *IamCrud) DeleteUser(input *iam.DeleteUserInput) (*iam.DeleteUserOutput, error) {
	user := &iam.User{}
	err := BH().DeleteMatching(user, badgerhold.Where("UserName").Eq(input.UserName))

	if err != nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}
	return &iam.DeleteUserOutput{}, nil
}

func (c *IamCrud) DeleteUserPolicy(input *iam.DeleteUserPolicyInput) (*iam.DeleteUserPolicyOutput, error) {
	uip := &UserInlinePolicy{}
	userArn := GenerateIamArn(&c.AccountId, aws.String("user"), nil, input.UserName)
	err := BH().DeleteMatching(uip, badgerhold.Where("UserArn").Eq(userArn).And("PolicyName").Eq(input.PolicyName))
	if err != nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	return &iam.DeleteUserPolicyOutput{}, nil
}

func (c *IamCrud) DetachRolePolicy(input *iam.DetachRolePolicyInput) (*iam.DetachRolePolicyOutput, error) {
	rpa := &RolePolicyAttachement{}
	roleArn := GenerateIamArn(&c.AccountId, aws.String("role"), nil, input.RoleName)
	err := BH().DeleteMatching(rpa, badgerhold.Where("RoleArn").Eq(roleArn).And("PolicyArn").Eq(input.PolicyArn))
	if err != nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	return &iam.DetachRolePolicyOutput{}, nil
}

func (c *IamCrud) DetachUserPolicy(input *iam.DetachUserPolicyInput) (*iam.DetachUserPolicyOutput, error) {
	upa := &UserPolicyAttachement{}
	userArn := GenerateIamArn(&c.AccountId, aws.String("user"), nil, input.UserName)
	err := BH().DeleteMatching(upa, badgerhold.Where("UserArn").Eq(userArn).And("PolicyArn").Eq(input.PolicyArn))
	if err != nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	return &iam.DetachUserPolicyOutput{}, nil
}

func (c *IamCrud) GetPolicy(input *iam.GetPolicyInput) (*iam.GetPolicyOutput, error) {
	policy := &iam.Policy{}
	err := BH().Get(input.PolicyArn, policy)
	if err != nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}
	return &iam.GetPolicyOutput{
		Policy: policy,
	}, nil
}

func (c *IamCrud) GetPolicyVersion(input *iam.GetPolicyVersionInput) (*iam.GetPolicyVersionOutput, error) {
	pvw := &PolicyVersionWrapper{}

	err := BH().FindOne(pvw, badgerhold.Where("PolicyArn").Eq(input.PolicyArn).And("PolicyVersion.VersionId").Eq(input.VersionId))
	if err != nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	return &iam.GetPolicyVersionOutput{
		PolicyVersion: pvw.PolicyVersion,
	}, nil
}

func (c *IamCrud) GetRole(input *iam.GetRoleInput) (*iam.GetRoleOutput, error) {

	role := &iam.Role{}
	err := BH().FindOne(role, badgerhold.Where("RoleName").Eq(input.RoleName))
	if err != nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}
	return &iam.GetRoleOutput{
		Role: role,
	}, nil
}

func (c *IamCrud) loggedInUser() (*iam.User, error) {
	// we want to get the currently logged in user, check if we have it
  user := &iam.User{}
	akwrapper := AccessKeyWrapper{}
	err := BH().FindOne(&akwrapper, badgerhold.Where("AccessKey.AccessKeyId").Eq(c.AccessKeyId))
	if err != nil {
		// it doesn't exist yet
		cuo, err := c.CreateUser(&iam.CreateUserInput{
			UserName: aws.String("defaultUser"),
		})
		if err != nil {
			return nil, err
		}
		err = BH().Insert(badgerhold.NextSequence(), AccessKeyWrapper{
			UserArn: *cuo.User.Arn,
			AccessKey: &iam.AccessKey{
				AccessKeyId:     &c.AccessKeyId,
				CreateDate:      aws.Time(time.Now().UTC()),
				SecretAccessKey: aws.String("secret"),
				Status:          aws.String(iam.StatusTypeActive),
				UserName:        cuo.User.UserName,
			},
		})

    return cuo.User, err

	} else {
    // we already have a user for the accesskey, retrieve it
    err := BH().Get(akwrapper.UserArn, user)
    return user, err
	}
}

func (c *IamCrud) GetUser(input *iam.GetUserInput) (*iam.GetUserOutput, error) {
	user := &iam.User{}
  var err error

	if input.UserName == nil {
    user, err = c.loggedInUser()
	} else {
	  userArn := GenerateIamArn(&c.AccountId, aws.String("user"), nil, input.UserName)
	  err = BH().Get(userArn, user)
  }

	if err != nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}
	return &iam.GetUserOutput{
		User: user,
	}, nil
}

func (c *IamCrud) ListAccessKeys(input *iam.ListAccessKeysInput) (*iam.ListAccessKeysOutput, error) {
	accessKeys := []AccessKeyWrapper{}
	user := &iam.User{}
  var err error

	if input.UserName == nil {
    user, err = c.loggedInUser()
	} else {
	  userArn := GenerateIamArn(&c.AccountId, aws.String("user"), nil, input.UserName)
	  err = BH().Get(userArn, user)
  }
	if err != nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	err = BH().Find(&accessKeys, badgerhold.Where("UserArn").Eq(user.Arn))

	if err != nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	metadatas := []*iam.AccessKeyMetadata{}

	for _, el := range accessKeys {
		ak := el.AccessKey
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

	rpas := []RolePolicyAttachement{}
	roleArn := GenerateIamArn(&c.AccountId, aws.String("role"), nil, input.RoleName)
	err := BH().Find(&rpas, badgerhold.Where("RoleArn").Eq(roleArn))

	if err != nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	attachedPolicies := []*iam.AttachedPolicy{}
	for _, pw := range rpas {
		attachedPolicies = append(attachedPolicies, &iam.AttachedPolicy{
			PolicyArn:  &pw.PolicyArn,
			PolicyName: new(string),
		})
	}

	return &iam.ListAttachedRolePoliciesOutput{
		AttachedPolicies: attachedPolicies,
		IsTruncated:      new(bool),
		Marker:           new(string),
	}, nil
}

func (c *IamCrud) ListAttachedUserPolicies(input *iam.ListAttachedUserPoliciesInput) (*iam.ListAttachedUserPoliciesOutput, error) {
	upas := []UserPolicyAttachement{}
	userArn := GenerateIamArn(&c.AccountId, aws.String("user"), nil, input.UserName)
	err := BH().Find(&upas, badgerhold.Where("UserArn").Eq(userArn))

	if err != nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	attachedPolicies := []*iam.AttachedPolicy{}
	for _, pw := range upas {
		attachedPolicies = append(attachedPolicies, &iam.AttachedPolicy{
			PolicyArn:  &pw.PolicyArn,
			PolicyName: new(string),
		})
	}

	return &iam.ListAttachedUserPoliciesOutput{
		AttachedPolicies: attachedPolicies,
		IsTruncated:      new(bool),
		Marker:           new(string),
	}, nil
}

// TODO: Support some filter
func (c *IamCrud) ListPolicies(input *iam.ListPoliciesInput) (*iam.ListPoliciesOutput, error) {
	policies := []*iam.Policy{}
	err := BH().Find(&policies, nil)

	if err != nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	return &iam.ListPoliciesOutput{
		IsTruncated: aws.Bool(false),
		Policies:    policies,
	}, nil

}

func (c *IamCrud) ListPolicyVersions(input *iam.ListPolicyVersionsInput) (*iam.ListPolicyVersionsOutput, error) {
	pvws := []PolicyVersionWrapper{}
	err := BH().Find(&pvws, badgerhold.Where("PolicyAnr").Eq(input.PolicyArn))

	if err != nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}
	versions := make([]*iam.PolicyVersion, len(pvws))

	for i, pw := range pvws {
		versions[i] = pw.PolicyVersion
	}

	return &iam.ListPolicyVersionsOutput{
		IsTruncated: aws.Bool(false),
		Versions:    versions,
	}, nil
}

// TODO: Support some filter
func (c *IamCrud) ListRoles(input *iam.ListRolesInput) (*iam.ListRolesOutput, error) {

	roles := []*iam.Role{}
	err := BH().Find(&roles, nil)

	if err != nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	return &iam.ListRolesOutput{
		IsTruncated: aws.Bool(false),
		Roles:       roles,
	}, nil

}

func (c *IamCrud) ListUserPolicies(input *iam.ListUserPoliciesInput) (*iam.ListUserPoliciesOutput, error) {
	uips := []UserInlinePolicy{}
	userArn := GenerateIamArn(&c.AccountId, aws.String("user"), nil, input.UserName)

	err := BH().Find(&uips, badgerhold.Where("UserArn").Eq(userArn))
	if err != nil {
		return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "", nil)
	}

	policyNames := make([]*string, len(uips))

	for i, pw := range uips {
		policyNames[i] = &pw.PolicyName
	}
	return &iam.ListUserPoliciesOutput{
		PolicyNames: policyNames,
	}, nil
}

func (c *IamCrud) ListUserTags(input *iam.ListUserTagsInput) (*iam.ListUserTagsOutput, error) {
	panic("Not Implemented")
}

func (c *IamCrud) ListUsers(input *iam.ListUsersInput) (*iam.ListUsersOutput, error) {
	panic("Not Implemented")
}

func (c *IamCrud) ListUsersPages(input *iam.ListUsersInput, fn func(*iam.ListUsersOutput, bool) bool) error {
	users := []*iam.User{}
	err := BH().Find(&users, nil)
	if err != nil {
		return err
	}

	fn(&iam.ListUsersOutput{
		IsTruncated: aws.Bool(false),
		Users:       users,
	}, false)
	return nil
}

func (c *IamCrud) PutUserPolicy(input *iam.PutUserPolicyInput) (*iam.PutUserPolicyOutput, error) {

	userArn := GenerateIamArn(&c.AccountId, aws.String("user"), nil, input.UserName)
	err := BH().Insert(badgerhold.NextSequence(), UserInlinePolicy{
		PolicyName:     *input.PolicyName,
		PolicyDocument: *input.PolicyDocument,
		UserArn:        userArn,
	})

	if err != nil {
		return nil, awserr.New(iam.ErrCodeInvalidInputException, "", nil)
	}

	return &iam.PutUserPolicyOutput{}, nil
}
