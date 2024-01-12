package goawscrudclient

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/timshannon/badgerhold/v4"
)

var availableInstances []string = []string{
	"t2.micro",
	"t3.micro",
}

var availableRegions []string = []string{
	"ap-south-2",
	"ap-south-1",
	"eu-south-1",
	"eu-south-2",
	"me-central-1",
	"ca-central-1",
	"eu-central-1",
	"eu-central-2",
	"us-west-1",
	"us-west-2",
	"af-south-1",
	"eu-north-1",
	"eu-west-3",
	"eu-west-2",
	"eu-west-1",
	"ap-northeast-3",
	"ap-northeast-2",
	"me-south-1",
	"ap-northeast-1",
	"sa-east-1",
	"ap-east-1",
	"ap-southeast-1",
	"ap-southeast-2",
	"ap-southeast-3",
	"ap-southeast-4",
	"us-east-1",
	"us-east-2",
}

type Ec2Crud struct {
	ec2iface.EC2API
	AccountId string
	Region    string
}

func NewVpcId() string {
	return fmt.Sprintf("vpc-%s", NewRandomId())
}
func NewSubnetId() string {
	return fmt.Sprintf("subnet-%s", NewRandomId())
}

func NewSubnetArn(region string, accountId string, subnetId string) string {
	return fmt.Sprintf("arn:aws:ec2:%s:%s:subnet/%s", region, accountId, subnetId)
}

func NewRandomId() string {
	num := rand.Int63()
	num = num%900000000000 + 100000000000
	return fmt.Sprintf("%d", num)
}

type VpcWrapper struct {
	Arn string
	Vpc *ec2.Vpc
}

func GenerateEc2Arn(accountID *string, region *string, resource *string, id *string) string {
	accValue := ""
	if accountID != nil {
		accValue = *accountID
	}

	resourceValue := ""
	if resource != nil {
		resourceValue = *resource
	}

	regionValue := ""
	if region != nil {
		regionValue = *region
	}

	nameValue := ""
	if id != nil {
		nameValue = *id
	}

	return fmt.Sprintf("arn:aws:iam:%s:%s:%s/%s", regionValue, accValue, resourceValue, nameValue)
}

func (c *Ec2Crud) CreateVpc(input *ec2.CreateVpcInput) (*ec2.CreateVpcOutput, error) {
	stateAvail := ec2.VpcStateAvailable

	id := NewVpcId()
	arn := GenerateEc2Arn(&c.AccountId, &c.Region, aws.String("vpc"), &id)

	tags := []*ec2.Tag{}
	for _, ts := range input.TagSpecifications {
		tags = append(tags, ts.Tags...)
	}

	cidrBlockAssociations := []*ec2.VpcCidrBlockAssociation{{
		AssociationId: aws.String(fmt.Sprintf("vpc-cidr-assoc-%s", NewRandomId())),
		CidrBlock:     input.CidrBlock,
		CidrBlockState: &ec2.VpcCidrBlockState{
			State: aws.String("associated"),
		},
	}}

	newVpc := &ec2.Vpc{
		CidrBlock:               input.CidrBlock,
		CidrBlockAssociationSet: cidrBlockAssociations,
		InstanceTenancy:         input.InstanceTenancy,
		IsDefault:               aws.Bool(false),
		OwnerId:                 &c.AccountId,
		State:                   &stateAvail,
		Tags:                    tags,
		VpcId:                   &id,
	}

	err := BH().Insert(arn, VpcWrapper{
		Arn: arn,
		Vpc: newVpc,
	})
	if err != nil {
		return nil, err
	}

	return &ec2.CreateVpcOutput{
		Vpc: newVpc,
	}, nil
}

func (c *Ec2Crud) CreateSubnet(input *ec2.CreateSubnetInput) (*ec2.CreateSubnetOutput, error) {

	tags := []*ec2.Tag{}
	for _, ts := range input.TagSpecifications {
		tags = append(tags, ts.Tags...)
	}

	id := NewSubnetId()
	subnetArn := GenerateEc2Arn(&c.AccountId, &c.Region, aws.String("subnet"), &id)
	subnet := &ec2.Subnet{
		AvailabilityZone:        input.AvailabilityZone,
		AvailabilityZoneId:      input.AvailabilityZoneId,
		AvailableIpAddressCount: aws.Int64(100),
		CidrBlock:               input.CidrBlock,
		DefaultForAz:            aws.Bool(false),
		Ipv6Native:              input.Ipv6Native,
		OutpostArn:              input.OutpostArn,
		OwnerId:                 &c.AccountId,
		State:                   aws.String("available"),
		SubnetArn:               &subnetArn,
		SubnetId:                &id,
		Tags:                    tags,
		VpcId:                   input.VpcId,
	}

	err := BH().Insert(subnetArn, subnet)
	if err != nil {
		return nil, err
	}

	return &ec2.CreateSubnetOutput{
		Subnet: subnet,
	}, nil
}

func (c *Ec2Crud) DeleteSnapshot(input *ec2.DeleteSnapshotInput) (*ec2.DeleteSnapshotOutput, error) {
	return &ec2.DeleteSnapshotOutput{}, nil
}
func (c *Ec2Crud) DeleteSubnet(input *ec2.DeleteSubnetInput) (*ec2.DeleteSubnetOutput, error) {
	snet := &ec2.Subnet{}
	subnetArn := GenerateEc2Arn(&c.AccountId, &c.Region, aws.String("subnet"), input.SubnetId)
	err := BH().Get(subnetArn, snet)
	if err != nil {
		return nil, err
	}

	return &ec2.DeleteSubnetOutput{}, nil
}
func (c *Ec2Crud) DeleteVolume(input *ec2.DeleteVolumeInput) (*ec2.DeleteVolumeOutput, error) {
	return &ec2.DeleteVolumeOutput{}, nil
}
func (c *Ec2Crud) DeleteVpc(input *ec2.DeleteVpcInput) (*ec2.DeleteVpcOutput, error) {
	vpcWrapper := VpcWrapper{}
	vpcArn := GenerateEc2Arn(&c.AccountId, &c.Region, aws.String("vpc"), input.VpcId)
	err := BH().Delete(vpcArn, vpcWrapper)
	return &ec2.DeleteVpcOutput{}, err
}

func (c *Ec2Crud) DeleteVpcEndpointServiceConfigurations(input *ec2.DeleteVpcEndpointServiceConfigurationsInput) (*ec2.DeleteVpcEndpointServiceConfigurationsOutput, error) {
	return &ec2.DeleteVpcEndpointServiceConfigurationsOutput{}, nil
}


func (c *Ec2Crud) DescribeImages(input *ec2.DescribeImagesInput) (*ec2.DescribeImagesOutput, error) {
	amis := []*ec2.Image{}
	err := BH().Find(&amis, nil)
	if err != nil {
		return nil, err
	}
	return &ec2.DescribeImagesOutput{
		Images: []*ec2.Image{{
			Architecture:        aws.String("x86_64"),
			ImageId:             aws.String("im-12345"),
			Name:                aws.String("RHEL"),
		}},
	}, nil
}

type InstanceWrapper struct {
	Arn      string
	Instance *ec2.Instance
}

func (c *Ec2Crud) DescribeInstanceStatus(input *ec2.DescribeInstanceStatusInput) (*ec2.DescribeInstanceStatusOutput, error) {
	instances := []InstanceWrapper{}
	var err error
	if len(input.InstanceIds) > 0 {
		instanceArns := []interface{}{}
		for _, v := range input.InstanceIds {
			curArn := GenerateEc2Arn(&c.AccountId, &c.Region, aws.String("instance"), v)
			instanceArns = append(instanceArns, curArn)
		}
		err = BH().Find(&instances, badgerhold.Where(badgerhold.Key).In(instanceArns...))
	} else {
		// just use all instances in this region & account
		arn := GenerateEc2Arn(&c.AccountId, &c.Region, aws.String("instance"), nil)
		err = BH().Find(&instances, badgerhold.Where(badgerhold.Key).HasPrefix(arn))
	}

	if err != nil {
		return nil, err
	}

	instanceStatuses := []*ec2.InstanceStatus{}

	for _, v := range instances {
		instanceStatuses = append(instanceStatuses, &ec2.InstanceStatus{
			AvailabilityZone: v.Instance.SubnetId,
			Events:           []*ec2.InstanceStatusEvent{},
			InstanceId:       v.Instance.InstanceId,
			InstanceState:    v.Instance.State,
			InstanceStatus: &ec2.InstanceStatusSummary{
				Status: aws.String("ok"),
			},
			OutpostArn: v.Instance.OutpostArn,
		})
	}

	return &ec2.DescribeInstanceStatusOutput{
		InstanceStatuses: instanceStatuses,
		NextToken:        new(string),
	}, nil
}

func (c *Ec2Crud) DescribeInstanceTypes(input *ec2.DescribeInstanceTypesInput) (*ec2.DescribeInstanceTypesOutput, error) {

	instanceTypeInfos := []*ec2.InstanceTypeInfo{}
	for _, availableType := range availableInstances {
		if len(input.InstanceTypes) != 0 {
			found := false
			for _, requestedType := range input.InstanceTypes {
				if availableType == *requestedType {
					found = true
				}
			}
			if !found {
				continue
			}
		}
		instanceTypeInfos = append(instanceTypeInfos, &ec2.InstanceTypeInfo{
			InstanceType: aws.String(availableType),
		})
	}

	return &ec2.DescribeInstanceTypesOutput{
		InstanceTypes: instanceTypeInfos,
	}, nil
}

func (c *Ec2Crud) DescribeInstances(input *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {

	instances := []InstanceWrapper{}
	var err error
	if len(input.InstanceIds) > 0 {
		instanceArns := []interface{}{}
		for _, v := range input.InstanceIds {
			curArn := GenerateEc2Arn(&c.AccountId, &c.Region, aws.String("instance"), v)
			instanceArns = append(instanceArns, curArn)
		}
		err = BH().Find(&instances, badgerhold.Where(badgerhold.Key).In(instanceArns...))
	} else {
		// just use all instances in this region & account
		arn := GenerateEc2Arn(&c.AccountId, &c.Region, aws.String("instance"), nil)
		err = BH().Find(&instances, badgerhold.Where(badgerhold.Key).HasPrefix(arn))
	}

	if err != nil {
		return nil, err
	}

	reservations := []*ec2.Reservation{}
	for _, i2 := range instances {
		reservations = append(reservations, &ec2.Reservation{
			Instances:     []*ec2.Instance{i2.Instance},
			OwnerId:       &c.AccountId,
			ReservationId: aws.String(fmt.Sprintf("r-%s", NewRandomId())),
		})
	}

	return &ec2.DescribeInstancesOutput{
		Reservations: reservations,
	}, nil
}

func (c *Ec2Crud) DescribeRegions(input *ec2.DescribeRegionsInput) (*ec2.DescribeRegionsOutput, error) {
	regs := []*ec2.Region{}
	for _, v := range availableRegions {
		regs = append(regs, &ec2.Region{
			OptInStatus: aws.String("opt-in-not-required"),
			RegionName:  aws.String(v),
		})
	}
	return &ec2.DescribeRegionsOutput{
		Regions: regs,
	}, nil
}

func (c *Ec2Crud) DescribeSnapshots(input *ec2.DescribeSnapshotsInput) (*ec2.DescribeSnapshotsOutput, error) {
	return &ec2.DescribeSnapshotsOutput{
		Snapshots: []*ec2.Snapshot{},
	}, nil
}

func (c *Ec2Crud) DescribeSubnets(input *ec2.DescribeSubnetsInput) (*ec2.DescribeSubnetsOutput, error) {

	subnets := []*ec2.Subnet{}

	if len(input.SubnetIds) >= 0 {
		subnetArnsBadger := []interface{}{}
		for _, v := range input.SubnetIds {
			curArn := GenerateEc2Arn(&c.AccountId, &c.Region, aws.String("subnet"), v)
			subnetArnsBadger = append(subnetArnsBadger, curArn)
		}
		err := BH().Find(&subnets, badgerhold.Where(badgerhold.Key).In(subnetArnsBadger...))
		if err != nil {
			return nil, err
		}
	} else {
		curArn := GenerateEc2Arn(&c.AccountId, &c.Region, aws.String("subnet"), nil)
		err := BH().Find(&subnets, badgerhold.Where(badgerhold.Key).HasPrefix(curArn))
		if err != nil {
			return nil, err
		}
	}

	return &ec2.DescribeSubnetsOutput{
		Subnets: subnets,
	}, nil
}

func (c *Ec2Crud) DescribeVolumes(input *ec2.DescribeVolumesInput) (*ec2.DescribeVolumesOutput, error) {
	return &ec2.DescribeVolumesOutput{
		Volumes: []*ec2.Volume{},
	}, nil
}

func (c *Ec2Crud) DescribeVpcEndpointServiceConfigurations(input *ec2.DescribeVpcEndpointServiceConfigurationsInput) (*ec2.DescribeVpcEndpointServiceConfigurationsOutput, error) {
	return &ec2.DescribeVpcEndpointServiceConfigurationsOutput{
		ServiceConfigurations: []*ec2.ServiceConfiguration{},
	}, nil
}

func (c *Ec2Crud) DescribeVpcs(input *ec2.DescribeVpcsInput) (*ec2.DescribeVpcsOutput, error) {
	vpcWrappers := []VpcWrapper{}

	if len(input.VpcIds) >= 0 {
		vpcArnsBadger := []interface{}{}
		for _, v := range input.VpcIds {
			curArn := GenerateEc2Arn(&c.AccountId, &c.Region, aws.String("vpc"), v)
			vpcArnsBadger = append(vpcArnsBadger, curArn)
		}
		err := BH().Find(&vpcWrappers, badgerhold.Where(badgerhold.Key).In(vpcArnsBadger...))
		if err != nil {
			return nil, err
		}
	} else {
		curArn := GenerateEc2Arn(&c.AccountId, &c.Region, aws.String("vpc"), nil)
		err := BH().Find(&vpcWrappers, badgerhold.Where(badgerhold.Key).HasPrefix(curArn))
		if err != nil {
			return nil, err
		}
	}

	vpcs := []*ec2.Vpc{}
	for _, vw := range vpcWrappers {
		vpcs = append(vpcs, vw.Vpc)
	}

	return &ec2.DescribeVpcsOutput{
		Vpcs: vpcs,
	}, nil
}

func (c *Ec2Crud) RunInstances(input *ec2.RunInstancesInput) (*ec2.Reservation, error) {
	instanceId := fmt.Sprintf("i-%s", NewRandomId())

	secGroupIdentifiers := []*ec2.GroupIdentifier{}

	for _, v := range input.SecurityGroupIds {
		secGroupIdentifiers = append(secGroupIdentifiers, &ec2.GroupIdentifier{
			GroupId: v,
		})
	}

	tags := []*ec2.Tag{}
	for _, ts := range input.TagSpecifications {
		tags = append(tags, ts.Tags...)
	}

	subnet := ec2.Subnet{}
	snetArn := GenerateEc2Arn(&c.AccountId, &c.Region, aws.String("subnet"), input.SubnetId)
	err := BH().FindOne(&subnet, badgerhold.Where(badgerhold.Key).HasPrefix(snetArn))

	if err != nil {
    return &ec2.Reservation{}, awserr.New("GenericBadgerError", snetArn, err)
	}

	newInstance := &ec2.Instance{
		AmiLaunchIndex:      aws.Int64(0),
		BlockDeviceMappings: []*ec2.InstanceBlockDeviceMapping{},
		ClientToken:         input.ClientToken,
		EbsOptimized:        input.EbsOptimized,
		ImageId:             input.ImageId,
		InstanceId:          &instanceId,
		InstanceType:        input.InstanceType,
		KeyName:             input.KeyName,
		LaunchTime:          aws.Time(time.Now().UTC()),
		RootDeviceName:      aws.String("/dev/sda1"),
		RootDeviceType:      aws.String("ebs"),
		SecurityGroups:      secGroupIdentifiers,
		SourceDestCheck:     aws.Bool(false),
		State: &ec2.InstanceState{
			Code: aws.Int64(16),
			Name: aws.String(ec2.InstanceStateNameRunning),
		},
		SubnetId: subnet.SubnetId,
		Tags:     tags,
		VpcId:    subnet.VpcId,
	}

	instanceArn := GenerateEc2Arn(&c.AccountId, &c.Region, aws.String("instance"), &instanceId)

	err = BH().Insert(instanceArn, InstanceWrapper{
		Arn:      instanceArn,
		Instance: newInstance,
	})
	if err != nil {
    return &ec2.Reservation{}, awserr.New("GenericBadgerError", "", err)
	}
	return &ec2.Reservation{
		Instances:     []*ec2.Instance{newInstance},
		OwnerId:       &c.AccountId,
		ReservationId: aws.String(fmt.Sprintf("r-%s", NewRandomId())),
	}, nil
}

func (c *Ec2Crud) TerminateInstances(input *ec2.TerminateInstancesInput) (*ec2.TerminateInstancesOutput, error) {

	stateChanges := []*ec2.InstanceStateChange{}

	for _, v := range input.InstanceIds {
		newStateChange := &ec2.InstanceStateChange{
			InstanceId: aws.String(*v),
		}
		curInstance := InstanceWrapper{}
    curInstanceArn := GenerateEc2Arn(&c.AccountId, &c.Region, aws.String("instance"), v)
		err := BH().Get(curInstanceArn, &curInstance)
		if err != nil {
			return nil, err
		}
		newStateChange.CurrentState = curInstance.Instance.State
		curInstance.Instance.State = &ec2.InstanceState{
			Name: aws.String(ec2.InstanceStateNameShuttingDown),
			Code: aws.Int64(32),
		}
		newStateChange.CurrentState = curInstance.Instance.State
    err = BH().Update(curInstanceArn, curInstance)
    if err != nil {
      return nil, err
    }
	}

	return &ec2.TerminateInstancesOutput{
		TerminatingInstances: stateChanges,
	}, nil
}
