all
# https://github.com/markdownlint/markdownlint/blob/master/docs/RULES.md#md003---header-style
rule 'MD003', :style => :setext_with_atx
# https://github.com/markdownlint/markdownlint/blob/master/docs/RULES.md#md013---line-length
rule 'MD013', :line_length => 88
# https://github.com/markdownlint/markdownlint/blob/master/docs/RULES.md#md029---ordered-list-item-prefix
rule 'MD029', :style => :ordered
# https://github.com/markdownlint/markdownlint/blob/master/docs/RULES.md#md024---multiple-headers-with-the-same-content
rule "MD024", :allow_different_nesting => true
