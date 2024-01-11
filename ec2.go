package goawscrudclient

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/aws/aws-sdk-go/aws"
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

func (c *Ec2Crud) CreateVpc(input *ec2.CreateVpcInput) (*ec2.CreateVpcOutput, error) {
	stateAvail := ec2.VpcStateAvailable

	id := NewVpcId()

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

	err := BH().Insert(id, newVpc)
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
	subnetArn := NewSubnetArn(c.Region, c.AccountId, id)
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

	err := BH().Insert(id, subnet)
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
	err := BH().Get(input.SubnetId, snet)
	if err != nil {
		return nil, err
	}

	return &ec2.DeleteSubnetOutput{}, nil
}
func (c *Ec2Crud) DeleteVolume(input *ec2.DeleteVolumeInput) (*ec2.DeleteVolumeOutput, error) {
	return &ec2.DeleteVolumeOutput{}, nil
}
func (c *Ec2Crud) DeleteVpc(input *ec2.DeleteVpcInput) (*ec2.DeleteVpcOutput, error) {
	vpc := &ec2.Vpc{}
	err := BH().Delete(input.VpcId, vpc)
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
		Images: amis,
	}, nil
}
func (c *Ec2Crud) DescribeInstanceStatus(input *ec2.DescribeInstanceStatusInput) (*ec2.DescribeInstanceStatusOutput, error) {
	instances := []*ec2.Instance{}
	instanceIdsBadger := []interface{}{}
	for _, v := range input.InstanceIds {
		instanceIdsBadger = append(instanceIdsBadger, v)
	}

	err := BH().Find(&instances, badgerhold.Where("InstanceId").In(instanceIdsBadger...))
	if err != nil {
		return nil, err
	}

	instanceStatuses := []*ec2.InstanceStatus{}

	for _, v := range instances {
		instanceStatuses = append(instanceStatuses, &ec2.InstanceStatus{
			AvailabilityZone: v.SubnetId,
			Events:           []*ec2.InstanceStatusEvent{},
			InstanceId:       v.InstanceId,
			InstanceState:    v.State,
			InstanceStatus: &ec2.InstanceStatusSummary{
				Status: aws.String("ok"),
			},
			OutpostArn: v.OutpostArn,
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
	instanceIdsBadger := []interface{}{}

	for _, v := range input.InstanceIds {
		instanceIdsBadger = append(instanceIdsBadger, v)
	}
	instances := []*ec2.Instance{}
	err := BH().Find(&instances, badgerhold.Where("InstanceId").In(instanceIdsBadger...))

	if err != nil {
		return nil, err
	}

	reservations := []*ec2.Reservation{}
	for _, i2 := range instances {
		reservations = append(reservations, &ec2.Reservation{
			Instances:     []*ec2.Instance{i2},
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
		subnetIdsBadger := []interface{}{}
		for _, v := range input.SubnetIds {
			subnetIdsBadger = append(subnetIdsBadger, v)
		}
		err := BH().Find(&subnets, badgerhold.Where("SubnetId").In(subnetIdsBadger...))
		if err != nil {
			return nil, err
		}
	} else {
		err := BH().Find(&subnets, nil)
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
	vpcs := []*ec2.Vpc{}

	if len(input.VpcIds) >= 0 {
		vpcIdsBadger := []interface{}{}
		for _, v := range input.VpcIds {
			vpcIdsBadger = append(vpcIdsBadger, v)
		}
		err := BH().Find(&vpcs, badgerhold.Where("VpcId").In(vpcIdsBadger...))
		if err != nil {
			return nil, err
		}
	} else {
		err := BH().Find(&vpcs, nil)
		if err != nil {
			return nil, err
		}
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
  if input.SubnetId == nil {
    
  }
	err := BH().Get(input.SubnetId, &subnet)

	if err != nil {
		return nil, err
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
		SubnetId: input.SubnetId,
		Tags:     tags,
		VpcId:    subnet.VpcId,
	}

	err = BH().Insert(instanceId, newInstance)
	if err != nil {
		return nil, err
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
			InstanceId:    aws.String(*v),
		}
		curInstance := ec2.Instance{}
		err := BH().Get(v, &curInstance)
		if err != nil {
			return nil, err
		}
    newStateChange.CurrentState = curInstance.State
    curInstance.State  = &ec2.InstanceState{
      Name: aws.String(ec2.InstanceStateNameShuttingDown),
      Code: aws.Int64(32),
    }
    newStateChange.CurrentState = curInstance.State
		BH().Update(v, curInstance)
	}

	return &ec2.TerminateInstancesOutput{
		TerminatingInstances: stateChanges,
	}, nil
}
