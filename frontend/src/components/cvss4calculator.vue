<template>
    <q-card class="cvss4calculator">
        <!-- Header with Score -->
        <q-card-section class="row">
            <div class="col-md-3" style="align-self:center">
                <span>
                    {{$t('cvss4.title')}}
                    <q-tooltip :anchor="tooltip.anchor" :self="tooltip.self" :delay="tooltip.delay" :max-width="tooltip.maxWidth">
                        <span :style="tooltip.style">{{$t('cvss4.tooltip.baseMetricGroup_Legend')}}</span>
                    </q-tooltip>
                </span>
            </div>
            <q-space />
            <div class="scoreRating" :class="cvss4.baseSeverity">
                <div v-if="cvss4.baseScore >= 0">
                    <span class="baseMetricScore">{{cvss4.baseScore}}</span>
                    <span class="baseSeverity">({{cvss4.baseSeverity}})</span>
                </div>
                <span class="baseSeverity" v-else>{{$t('cvss4.infoWhenNoScore')}}</span>
            </div>
        </q-card-section>
        
        <q-separator />
        
        <!-- Exploitability Metrics - Compact Layout -->
        <h6 class="q-mb-none q-mt-md q-ml-md">{{$t('cvss4.exploitabilityMetric')}}</h6>
        <q-card-section class="row q-col-gutter-sm">
            <!-- Row 1: Attack Vector & Attack Complexity -->
            <div class="col-md-6 col-12">
                <div class="text-weight-bold q-mb-xs">
                    {{$t('cvss4.attackVector')}}
                    <q-tooltip :anchor="tooltip.anchor" :self="tooltip.self" :delay="tooltip.delay">
                        <span :style="tooltip.style">{{$t('cvss4.tooltip.AV_Heading')}}</span>
                    </q-tooltip>
                </div>
                <q-btn-toggle 
                    v-model="cvss4.AV" 
                    :options="attackVectorOptions"
                    dense
                    size="sm"
                    class="q-mb-md"
                />
            </div>
            
            <div class="col-md-6 col-12">
                <div class="text-weight-bold q-mb-xs">
                    {{$t('cvss4.attackComplexity')}}
                    <q-tooltip :anchor="tooltip.anchor" :self="tooltip.self" :delay="tooltip.delay">
                        <span :style="tooltip.style">{{$t('cvss4.tooltip.AC_Heading')}}</span>
                    </q-tooltip>
                </div>
                <q-btn-toggle 
                    v-model="cvss4.AC" 
                    :options="attackComplexityOptions"
                    dense
                    size="sm"
                    class="q-mb-md"
                />
            </div>
            
            <!-- Row 2: Attack Requirements & Privileges Required -->
            <div class="col-md-6 col-12">
                <div class="text-weight-bold q-mb-xs">
                    {{$t('cvss4.attackRequirements')}}
                    <q-tooltip :anchor="tooltip.anchor" :self="tooltip.self" :delay="tooltip.delay">
                        <span :style="tooltip.style">{{$t('cvss4.tooltip.AT_Heading')}}</span>
                    </q-tooltip>
                </div>
                <q-btn-toggle 
                    v-model="cvss4.AT" 
                    :options="attackRequirementsOptions"
                    dense
                    size="sm"
                    class="q-mb-md"
                />
            </div>
            
            <div class="col-md-6 col-12">
                <div class="text-weight-bold q-mb-xs">
                    {{$t('cvss4.privilegesRequired')}}
                    <q-tooltip :anchor="tooltip.anchor" :self="tooltip.self" :delay="tooltip.delay">
                        <span :style="tooltip.style">{{$t('cvss4.tooltip.PR_Heading')}}</span>
                    </q-tooltip>
                </div>
                <q-btn-toggle 
                    v-model="cvss4.PR" 
                    :options="privilegesRequiredOptions"
                    dense
                    size="sm"
                    class="q-mb-md"
                />
            </div>
            
            <!-- Row 3: User Interaction (centered) -->
            <div class="col-md-6 col-12">
                <div class="text-weight-bold q-mb-xs">
                    {{$t('cvss4.userInteraction')}}
                    <q-tooltip :anchor="tooltip.anchor" :self="tooltip.self" :delay="tooltip.delay">
                        <span :style="tooltip.style">{{$t('cvss4.tooltip.UI_Heading')}}</span>
                    </q-tooltip>
                </div>
                <q-btn-toggle 
                    v-model="cvss4.UI" 
                    :options="userInteractionOptions"
                    dense
                    size="sm"
                    class="q-mb-md"
                />
            </div>
        </q-card-section>

        <!-- Vulnerable System Impact Metrics -->
        <h6 class="q-mb-none q-mt-md q-ml-md">{{$t('cvss4.vulnerableSystemImpact')}}</h6>
        <q-card-section class="row q-col-gutter-sm">
            <div class="col-md-4 col-12">
                <div class="text-weight-bold q-mb-xs">
                    {{$t('cvss4.confidentiality')}}
                </div>
                <q-btn-toggle 
                    v-model="cvss4.VC" 
                    :options="impactOptions"
                    dense
                    size="sm"
                    class="q-mb-md"
                />
            </div>
            
            <div class="col-md-4 col-12">
                <div class="text-weight-bold q-mb-xs">
                    {{$t('cvss4.integrity')}}
                </div>
                <q-btn-toggle 
                    v-model="cvss4.VI" 
                    :options="impactOptions"
                    dense
                    size="sm"
                    class="q-mb-md"
                />
            </div>
            
            <div class="col-md-4 col-12">
                <div class="text-weight-bold q-mb-xs">
                    {{$t('cvss4.availability')}}
                </div>
                <q-btn-toggle 
                    v-model="cvss4.VA" 
                    :options="impactOptions"
                    dense
                    size="sm"
                    class="q-mb-md"
                />
            </div>
        </q-card-section>

        <!-- Subsequent System Impact Metrics -->
        <h6 class="q-mb-none q-mt-md q-ml-md">{{$t('cvss4.subsequentSystemImpact')}}</h6>
        <q-card-section class="row q-col-gutter-sm">
            <div class="col-md-4 col-12">
                <div class="text-weight-bold q-mb-xs">
                    {{$t('cvss4.confidentiality')}}
                </div>
                <q-btn-toggle 
                    v-model="cvss4.SC" 
                    :options="impactOptions"
                    dense
                    size="sm"
                    class="q-mb-md"
                />
            </div>
            
            <div class="col-md-4 col-12">
                <div class="text-weight-bold q-mb-xs">
                    {{$t('cvss4.integrity')}}
                </div>
                <q-btn-toggle 
                    v-model="cvss4.SI" 
                    :options="impactOptions"
                    dense
                    size="sm"
                    class="q-mb-md"
                />
            </div>
            
            <div class="col-md-4 col-12">
                <div class="text-weight-bold q-mb-xs">
                    {{$t('cvss4.availability')}}
                </div>
                <q-btn-toggle 
                    v-model="cvss4.SA" 
                    :options="impactOptions"
                    dense
                    size="sm"
                    class="q-mb-md"
                />
            </div>
        </q-card-section>
    </q-card>
</template>

<script>
export default {
    name: 'Cvss4Calculator',
    data() {
        return {
            cvss4: {
                baseScore: 0,
                baseSeverity: 'None',
                AV: '',
                AC: '',
                AT: '',
                PR: '',
                UI: '',
                VC: '',
                VI: '',
                VA: '',
                SC: '',
                SI: '',
                SA: ''
            },
            tooltip: {
                anchor: 'top middle',
                self: 'bottom middle',
                delay: 500,
                maxWidth: '300px',
                style: 'font-size: 12px'
            },
            attackVectorOptions: [
                {label: 'Network', value: 'N'},
                {label: 'Adjacent', value: 'A'},
                {label: 'Local', value: 'L'},
                {label: 'Physical', value: 'P'}
            ],
            attackComplexityOptions: [
                {label: 'Low', value: 'L'},
                {label: 'High', value: 'H'}
            ],
            attackRequirementsOptions: [
                {label: 'None', value: 'N'},
                {label: 'Present', value: 'P'}
            ],
            privilegesRequiredOptions: [
                {label: 'None', value: 'N'},
                {label: 'Low', value: 'L'},
                {label: 'High', value: 'H'}
            ],
            userInteractionOptions: [
                {label: 'None', value: 'N'},
                {label: 'Passive', value: 'P'},
                {label: 'Active', value: 'A'}
            ],
            impactOptions: [
                {label: 'None', value: 'N'},
                {label: 'Low', value: 'L'},
                {label: 'High', value: 'H'}
            ]
        }
    }
}
</script>

<style scoped>
.cvss4calculator .q-btn-toggle {
    border-radius: 4px;
}

.cvss4calculator .text-weight-bold {
    font-size: 0.9em;
    color: #555;
}

.scoreRating {
    padding: 8px 16px;
    border-radius: 4px;
    text-align: center;
    min-width: 80px;
}

.scoreRating.None { background-color: #6c757d; color: white; }
.scoreRating.Low { background-color: #28a745; color: white; }
.scoreRating.Medium { background-color: #ffc107; color: black; }
.scoreRating.High { background-color: #fd7e14; color: white; }
.scoreRating.Critical { background-color: #dc3545; color: white; }

.baseMetricScore {
    font-size: 1.2em;
    font-weight: bold;
}

.baseSeverity {
    font-size: 0.9em;
    margin-left: 4px;
}
</style>
