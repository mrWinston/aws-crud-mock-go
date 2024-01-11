package goawscrudclient

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/servicequotas"
	"github.com/aws/aws-sdk-go/service/servicequotas/servicequotasiface"
)

type ServiceQuotasCrud struct {
  servicequotasiface.ServiceQuotasAPI
}


func (c *ServiceQuotasCrud) GetServiceQuota(input *servicequotas.GetServiceQuotaInput) (*servicequotas.GetServiceQuotaOutput, error) {
  return &servicequotas.GetServiceQuotaOutput{
  	Quota: &servicequotas.ServiceQuota{
  		Adjustable:          aws.Bool(true),
  		QuotaCode:           input.QuotaCode,
  		ServiceCode:         input.ServiceCode,
  		Value:               aws.Float64(1000),
  	},
  }, nil
}
// func (c *ServiceQuotasCrud) RequestServiceQuotaIncrease(*servicequotas.RequestServiceQuotaIncreaseInput) (*servicequotas.RequestServiceQuotaIncreaseOutput, error)
// func (c *ServiceQuotasCrud) ListRequestedServiceQuotaChangeHistory(*servicequotas.ListRequestedServiceQuotaChangeHistoryInput) (*servicequotas.ListRequestedServiceQuotaChangeHistoryOutput, error)
// func (c *ServiceQuotasCrud) ListRequestedServiceQuotaChangeHistoryByQuota(*servicequotas.ListRequestedServiceQuotaChangeHistoryByQuotaInput) (*servicequotas.ListRequestedServiceQuotaChangeHistoryByQuotaOutput, error)
